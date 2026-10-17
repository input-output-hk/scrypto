package scorex.crypto.authds.avltree.batch.serialization

import org.scalacheck.{Gen, Shrink}
import org.scalatest.propspec.AnyPropSpec
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds.avltree.batch._
import scorex.crypto.authds.{ADKey, ADValue, TwoPartyTests}
import scorex.crypto.hash.{Blake2b256, _}
import scorex.util.encode.Base16
import scala.util.Random

class AVLBatchSerializationSpecification extends AnyPropSpec with ScalaCheckDrivenPropertyChecks with TwoPartyTests {

  val InitialTreeSize = 1000
  val KL = 26
  val VL = 8
  val HL = 32
  type D = Digest32
  type HF = Blake2b256.type
  implicit val hf: HF = Blake2b256

  implicit def noShrink[A]: Shrink[A] = Shrink(_ => Stream.empty)

  val serializer = new BatchAVLProverSerializer[D, HF]

  def slice(tree: BatchAVLProver[D, HF]) = serializer.slice(tree, tree.rootNodeHeight / 2)

  private def generateProver(size: Int = InitialTreeSize): BatchAVLProver[D, HF] = {
    val prover = new BatchAVLProver[D, HF](KL, None)
    val keyValues = (0 until size) map { i =>
      (ADKey @@ Blake2b256(i.toString.getBytes("UTF-8")).take(KL), ADValue @@ i.toString.getBytes("UTF-8"))
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))
    prover.generateProof()
    prover
  }

  property("slice to pieces and combine tree back") {
    forAll(Gen.choose(10, 10000)) { (treeSize: Int) =>
      whenever(treeSize >= 10) {
        val tree = generateProver(treeSize)
        val height = tree.rootNodeHeight
        val digest = tree.digest
        val sliced = slice(tree)

        val manifestLeftTree = leftTree(sliced._1.root)
        val subtreeLeftTree = leftTree(sliced._2.head.subtreeTop)

        manifestLeftTree.length should be < height
        manifestLeftTree.last.asInstanceOf[ProxyInternalNode[D]].leftLabel shouldEqual subtreeLeftTree.head.label

        val recovered = serializer.combine(sliced, tree.keyLength, tree.valueLengthOpt).get
        recovered.digest shouldEqual digest
        recovered.rootNodeHeight shouldEqual height
      }
    }
  }

  property("slice to Array[Byte] pieces and combine tree back") {
    forAll(Gen.choose(0, 10000)) { (treeSize: Int) =>
      val serializer = new BatchAVLProverSerializer[D, HF]
      val tree = generateProver(treeSize)
      val kl = tree.keyLength
      val digest = tree.digest

      val sliced = slice(tree)

      val manifestBytes = serializer.manifestToBytes(sliced._1)
      val subtreeBytes = sliced._2.map(t => serializer.subtreeToBytes(t))

      val recoveredManifest = serializer.manifestFromBytes(manifestBytes, tree.keyLength).get
      val recoveredSubtrees = subtreeBytes.map(b => serializer.subtreeFromBytes(b, kl).get)

      val subtreeBytes2 = recoveredSubtrees.map(t => serializer.subtreeToBytes(t))
      subtreeBytes.flatten shouldEqual subtreeBytes2.flatten

      val recoveredSliced = (recoveredManifest, recoveredSubtrees)
      val recovered = serializer.combine(recoveredSliced, tree.keyLength, tree.valueLengthOpt).get

      recovered.digest shouldEqual digest
    }
  }

  property("manifest serialization") {
    val serializer = new BatchAVLProverSerializer[D, HF]
    forAll(Gen.choose(0, 10000)) { (treeSize: Int) =>
      val tree = generateProver(treeSize)
      val kl = tree.keyLength
      val digest = tree.digest
      val sliced = slice(tree)

      val manifest = sliced._1
      val manifestBytes = serializer.manifestToBytes(manifest)
      val deserializedManifest = serializer.manifestFromBytes(manifestBytes, kl).get

      deserializedManifest.root.label shouldBe manifest.root.label
    }
  }

  property("wrong manifest & subtree bytes") {
    val tree = generateProver()
    val sliced = slice(tree)
    val manifest = sliced._1

    val subtreeId = manifest.subtreesIds(Random.nextInt(manifest.subtreesIds.size))

    val manifestBytes = serializer.manifestToBytes(manifest)
    val idx = manifestBytes.indexOfSlice(subtreeId)
    manifestBytes(idx) = ((manifestBytes(idx) + 1) % Byte.MaxValue).toByte
    val wrongManifest = serializer.manifestFromBytes(manifestBytes, tree.keyLength).get

    wrongManifest.verify(manifest.root.label, manifest.rootHeight) shouldBe false

    val subtree = sliced._2.head
    val subtreeBytes = serializer.subtreeToBytes(subtree)
    val value = subtree.leafValues.head
    val idx2 = subtreeBytes.indexOfSlice(value)
    subtreeBytes(idx2) = ((subtreeBytes(idx2) + 1) % Byte.MaxValue).toByte
    serializer.subtreeFromBytes(subtreeBytes, tree.keyLength)
      .get
      .verify(subtree.id) shouldBe false
  }

  property("verify manifest and subtrees") {
    val tree = generateProver()
    val sliced = slice(tree)
    val manifest = sliced._1
    manifest.verify(tree.topNode.label, tree.rootNodeHeight) shouldBe true
    val subtrees = sliced._2
    subtrees.forall(st => st.verify(st.id)) shouldBe true
  }

  property("subtreesIds for manifest") {
    val tree = generateProver()
    val sliced = slice(tree)
    val manifest = sliced._1
    val subtrees = sliced._2

    val manSubtrees = manifest.subtreesIds
    manSubtrees.size shouldBe subtrees.size
    manSubtrees.foreach{digest =>
      subtrees.exists(_.id.sameElements(digest)) shouldBe true
    }
    manSubtrees.map(Base16.encode).distinct.size shouldBe manSubtrees.size
  }

  property("reject forged internal node keys in subtree, manifest, and combine (issue #89)") {
    val tree = generateProver(200)
    val expectedDigest = tree.topNode.label
    val expectedHeight = tree.rootNodeHeight

    // 1. Subtree verification rejects forged internal key even though label is unchanged
    val (_, subtreesForSubtreeTest) = slice(tree)
    val nonLeafSubtree = subtreesForSubtreeTest.find(_.subtreeTop.isInstanceOf[InternalProverNode[D]]).get
    val originalSubtreeDigest = nonLeafSubtree.id
    val internalTop = nonLeafSubtree.subtreeTop.asInstanceOf[InternalProverNode[D]]
    val forgedKey = ADKey @@ internalTop.key.clone()
    forgedKey(forgedKey.length - 1) = (forgedKey(forgedKey.length - 1) ^ 1).toByte
    val mutatedTop = internalTop.getNewKey(forgedKey)
    // InternalProverNode label does not commit to the internal key
    mutatedTop.label shouldEqual originalSubtreeDigest
    val forgedSubtree = BatchAVLProverSubtree[D](mutatedTop)
    forgedSubtree.verify(originalSubtreeDigest) shouldBe false

    // 2. Manifest verification rejects out-of-order internal keys even though manifest root label is unchanged
    val (manifestForManifestTest, _) = slice(tree)
    val manifestRoot = manifestForManifestTest.root.asInstanceOf[InternalProverNode[D]]
    val leftInternal = manifestRoot.left.asInstanceOf[InternalProverNode[D]]
    // Forge left child's key to be greater than root's key; root label does not change
    leftInternal.getNewKey(manifestRoot.right.key)
    manifestForManifestTest.id shouldEqual expectedDigest
    manifestForManifestTest.verify(expectedDigest, expectedHeight) shouldBe false

    // 3. combine rejects forged manifest internal key even when manifest keys remain strictly ordered
    val (manifestForCombineTest, subtreesForCombineTest) = slice(tree)
    val combineRoot = manifestForCombineTest.root.asInstanceOf[InternalProverNode[D]]
    val nudgedRootKey = ADKey @@ combineRoot.key.clone()
    nudgedRootKey(nudgedRootKey.length - 1) = (nudgedRootKey(nudgedRootKey.length - 1) ^ 1).toByte
    combineRoot.getNewKey(nudgedRootKey)
    combineRoot.label shouldEqual expectedDigest
    serializer.combine((manifestForCombineTest, subtreesForCombineTest), tree.keyLength, tree.valueLengthOpt).isFailure shouldBe true

    // 4. combine also rejects forged subtree internal key
    val (cleanManifest, cleanSubtrees) = slice(tree)
    val idx = cleanSubtrees.indexWhere(_.subtreeTop.isInstanceOf[InternalProverNode[D]])
    val targetSubtree = cleanSubtrees(idx)
    val targetNode = targetSubtree.subtreeTop.asInstanceOf[InternalProverNode[D]]
    val badSubtreeKey = ADKey @@ targetNode.key.clone()
    badSubtreeKey(badSubtreeKey.length - 1) = (badSubtreeKey(badSubtreeKey.length - 1) ^ 1).toByte
    val badSubtrees = cleanSubtrees.updated(idx, BatchAVLProverSubtree[D](targetNode.getNewKey(badSubtreeKey)))
    serializer.combine((cleanManifest, badSubtrees), tree.keyLength, tree.valueLengthOpt).isFailure shouldBe true
  }

  def leftTree(n: ProverNodes[D]): Seq[ProverNodes[D]] = n match {
    case n: ProxyInternalNode[D] if n.isEmpty =>
      Seq(n)
    case n: InternalProverNode[D] =>
      n +: leftTree(n.left)
    case l: ProverLeaf[D] =>
      Seq(l)
  }

}
