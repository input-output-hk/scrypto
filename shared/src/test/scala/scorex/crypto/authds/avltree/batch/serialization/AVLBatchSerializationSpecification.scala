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

  private val forgedKey: ADKey = ADKey @@ Blake2b256("forged").take(KL)

  /** Same children and balance, different key - and therefore the same label */
  private def withForgedKey(n: InternalProverNode[D], key: ADKey = forgedKey): InternalProverNode[D] =
    new InternalProverNode[D](key, n.left, n.right, n.balance)

  private def firstInternalSubtree(sliced: serializer.SlicedTree): BatchAVLProverSubtree[D] =
    sliced._2.find(_.subtreeTop.isInstanceOf[InternalProverNode[D]]).get

  property("a label does not commit to the key of an internal node") {
    val tree = generateProver()
    val subtree = firstInternalSubtree(slice(tree))
    val top = subtree.subtreeTop.asInstanceOf[InternalProverNode[D]]

    val forged = withForgedKey(top)

    // this is the hole the checks below close: the key changed, the digest did not
    forged.key.sameElements(top.key) shouldBe false
    forged.label.sameElements(top.label) shouldBe true
  }

  property("subtree with a forged internal key does not verify") {
    val tree = generateProver()
    val subtree = firstInternalSubtree(slice(tree))
    val top = subtree.subtreeTop.asInstanceOf[InternalProverNode[D]]

    val forgedSubtree = BatchAVLProverSubtree[D](withForgedKey(top))

    // it still passes the digest check it used to be accepted on ...
    forgedSubtree.id.sameElements(subtree.id) shouldBe true
    // ... and is rejected anyway
    forgedSubtree.verify(subtree.id) shouldBe false

    subtree.verify(subtree.id) shouldBe true
  }

  property("manifest with an internal key out of order does not verify") {
    val tree = generateProver()
    val manifest = slice(tree)._1
    val root = manifest.root.asInstanceOf[InternalProverNode[D]]

    // smaller than every key in the tree, so the in-order walk stops increasing at the root
    val smallest = ADKey @@ Array.fill(KL)(0.toByte)
    val forgedManifest = BatchAVLProverManifest[D](withForgedKey(root, smallest), manifest.rootHeight)

    forgedManifest.id.sameElements(manifest.id) shouldBe true
    forgedManifest.verify(manifest.id, manifest.rootHeight) shouldBe false

    manifest.verify(manifest.id, manifest.rootHeight) shouldBe true
  }

  property("combining a tree with a forged internal key fails") {
    val tree = generateProver()

    // combine mutates the manifest it is given, so each case gets its own slice of the same tree
    serializer.combine(slice(tree), tree.keyLength, tree.valueLengthOpt).isSuccess shouldBe true

    val sliced = slice(tree)
    val subtree = firstInternalSubtree(sliced)
    val top = subtree.subtreeTop.asInstanceOf[InternalProverNode[D]]

    val forgedSubtree = BatchAVLProverSubtree[D](withForgedKey(top))
    val forgedSliced = (sliced._1, sliced._2.map(st => if (st.id.sameElements(subtree.id)) forgedSubtree else st))

    // the label is unchanged, so the forged subtree is still found and attached where the real one belongs
    serializer.combine(forgedSliced, tree.keyLength, tree.valueLengthOpt).isFailure shouldBe true
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
