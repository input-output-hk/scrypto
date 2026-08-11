package scorex.crypto.authds.avltree.batch.serialization

import org.scalacheck.{Gen, Shrink}
import org.scalatest.propspec.AnyPropSpec
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds.avltree.batch._
import scorex.crypto.authds.{ADKey, ADValue, Balance, TwoPartyTests}
import scorex.crypto.hash.{Blake2b256, _}
import scorex.util.encode.Base16
import scorex.utils.Ints

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

  private def generateProver(size: Int = InitialTreeSize, keyOffset: Int = 0): BatchAVLProver[D, HF] = {
    val prover = new BatchAVLProver[D, HF](KL, None)
    val keyValues = (0 until size) map { i =>
      val v = i + keyOffset
      (ADKey @@ Blake2b256(v.toString.getBytes("UTF-8")).take(KL), ADValue @@ v.toString.getBytes("UTF-8"))
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))
    prover.generateProof()
    prover
  }

  /** Build a fixed-size byte key from an integer value. Keys compare lexicographically by the last byte. */
  private def keyBytes(value: Int, length: Int): Array[Byte] = {
    val arr = new Array[Byte](length)
    arr(length - 1) = value.toByte
    arr
  }

  /** Build a right-skewed chain of internal nodes where each left child is a leaf.
    * Keys are chosen so the BST ordering check in nodesFromBytes passes for every level.
    * Keys increase from the bottom leaf (2*depth) up to the root (1).
    */
  private def rightSkewedChainBytes(depth: Int, keyLength: Int): Array[Byte] = {
    require(depth >= 0)

    def leafBytes(keyValue: Int): Array[Byte] = {
      Array(0.toByte) ++
        keyBytes(keyValue, keyLength) ++
        keyBytes(keyValue + 1, keyLength) ++
        Array(0.toByte) // one-byte value
    }

    def internalNodeBytes(keyValue: Int, leftBytes: Array[Byte], rightBytes: Array[Byte]): Array[Byte] = {
      val leftLengthBytes = Ints.toByteArray(leftBytes.length)
      Array(1.toByte, 0.toByte) ++
        keyBytes(keyValue, keyLength) ++
        leftLengthBytes ++
        leftBytes ++
        rightBytes
    }

    var current = leafBytes(2 * depth)
    for (i <- depth - 1 to 0 by -1) {
      val left = leafBytes(2 * i)
      current = internalNodeBytes(2 * i + 1, left, current)
    }
    current
  }

  /** Build a right-skewed chain of InternalProverNodes for in-memory depth tests. */
  private def deepInternalChain(depth: Int): ProverNodes[D] = {
    require(depth >= 0)
    var current: ProverNodes[D] = new ProverLeaf[D](
      ADKey @@ keyBytes(2 * depth, KL),
      ADValue @@ Array(0.toByte),
      ADKey @@ keyBytes(2 * depth + 1, KL)
    )
    for (i <- depth - 1 to 0 by -1) {
      val left = new ProverLeaf[D](
        ADKey @@ keyBytes(2 * i, KL),
        ADValue @@ Array(0.toByte),
        ADKey @@ keyBytes(2 * i + 1, KL)
      )
      current = new InternalProverNode[D](
        ADKey @@ keyBytes(2 * i + 1, KL),
        left,
        current,
        Balance @@ 0.toByte
      )
    }
    current
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

  property("combine accepts subtrees passed as a non-Array Seq") {
    val tree = generateProver()
    val digest = tree.digest
    val sliced = slice(tree)
    // Downstream consumers may build the subtrees collection as a generic Seq (e.g. via .map),
    // which must not fail with a ClassCastException at runtime.
    val subtreesAsList = sliced._2.toList
    val recovered = serializer.combine((sliced._1, subtreesAsList), tree.keyLength, tree.valueLengthOpt).get
    recovered.digest shouldEqual digest
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
    // Skip sentinel leaves with empty values and pick a real leaf value to corrupt.
    val value = subtree.leafValues.filter(_.nonEmpty).head
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

  property("nodesFromBytes rejects trees deeper than maxDepth") {
    val depth = 10
    val maxDepth = 5
    val bytes = rightSkewedChainBytes(depth, KL)
    serializer.nodesFromBytes(bytes, KL, maxDepth).isFailure shouldBe true
  }

  property("nodesFromBytes accepts trees within maxDepth") {
    val depth = 5
    val maxDepth = 5
    val bytes = rightSkewedChainBytes(depth, KL)
    serializer.nodesFromBytes(bytes, KL, maxDepth).isSuccess shouldBe true
  }

  property("nodesFromBytes default maxDepth rejects trees deeper than 255") {
    val depth = 256
    val bytes = rightSkewedChainBytes(depth, KL)
    serializer.nodesFromBytes(bytes, KL).isFailure shouldBe true
  }

  property("manifestFromBytes rejects manifest deeper than declared height") {
    val actualDepth = 10
    val declaredHeight = 5
    val nodeBytes = rightSkewedChainBytes(actualDepth, KL)
    val manifestBytes = Ints.toByteArray(declaredHeight) ++ nodeBytes
    serializer.manifestFromBytes(manifestBytes, KL).isFailure shouldBe true
  }

  property("manifestFromBytes rejects height 256") {
    val nodeBytes = rightSkewedChainBytes(1, KL)
    val manifestBytes = Ints.toByteArray(256) ++ nodeBytes
    serializer.manifestFromBytes(manifestBytes, KL).isFailure shouldBe true
  }

  property("manifestFromBytes accepts height 255") {
    val nodeBytes = rightSkewedChainBytes(1, KL)
    val manifestBytes = Ints.toByteArray(255) ++ nodeBytes
    serializer.manifestFromBytes(manifestBytes, KL).isSuccess shouldBe true
  }

  property("subtreeFromBytes rejects trees deeper than 255") {
    val depth = 256
    val bytes = rightSkewedChainBytes(depth, KL)
    serializer.subtreeFromBytes(bytes, KL).isFailure shouldBe true
  }

  property("combine rejects manifests deeper than rootHeight") {
    val depth = 10
    val rootHeight = 5
    val root = deepInternalChain(depth)
    val manifest = BatchAVLProverManifest[D](root, rootHeight)
    serializer.combine((manifest, Array.empty[BatchAVLProverSubtree[D]]), KL, None).isFailure shouldBe true
  }

  property("combine rejects manifest with wrong height") {
    val actualDepth = 3
    val rootHeight = 5
    val root = deepInternalChain(actualDepth)
    val manifest = BatchAVLProverManifest[D](root, rootHeight)
    serializer.combine((manifest, Array.empty[BatchAVLProverSubtree[D]]), KL, None).isFailure shouldBe true
  }

  property("combine accepts manifest with matching height") {
    val depth = 3
    val root = deepInternalChain(depth)
    val manifest = BatchAVLProverManifest[D](root, depth)
    serializer.combine((manifest, Array.empty[BatchAVLProverSubtree[D]]), KL, None).isSuccess shouldBe true
  }

  property("nodesFromBytes rejects truncated leaf") {
    serializer.nodesFromBytes(Array(0.toByte), KL).isFailure shouldBe true
    serializer.nodesFromBytes(Array(0.toByte) ++ Array.fill(KL - 1)(0.toByte), KL).isFailure shouldBe true
    serializer.nodesFromBytes(Array(0.toByte) ++ Array.fill(KL)(0.toByte), KL).isFailure shouldBe true
    serializer.nodesFromBytes(Array(0.toByte) ++ Array.fill(2 * KL)(0.toByte), KL).isSuccess shouldBe true
  }

  property("nodesFromBytes rejects non-positive keyLength") {
    serializer.nodesFromBytes(Array(0.toByte), 0).isFailure shouldBe true
    serializer.nodesFromBytes(Array(0.toByte), -1).isFailure shouldBe true
  }

  property("nodesFromBytes rejects internal node with leftLength consuming all remaining bytes") {
    val leaf = Array(0.toByte) ++ keyBytes(0, KL) ++ keyBytes(1, KL) ++ Array(0.toByte)
    val leftLength = leaf.length
    val bytes = Array(1.toByte, 0.toByte) ++ keyBytes(2, KL) ++ Ints.toByteArray(leftLength) ++ leaf
    serializer.nodesFromBytes(bytes, KL).isFailure shouldBe true
  }

  property("nodesFromBytes rejects invalid balance in internal node") {
    val leaf = Array(0.toByte) ++ keyBytes(0, KL) ++ keyBytes(1, KL) ++ Array(0.toByte)
    val bytes = Array(1.toByte, 2.toByte) ++ keyBytes(2, KL) ++ Ints.toByteArray(leaf.length) ++ leaf ++ leaf
    serializer.nodesFromBytes(bytes, KL).isFailure shouldBe true

    val bytesNegative = Array(1.toByte, -2.toByte) ++ keyBytes(2, KL) ++ Ints.toByteArray(leaf.length) ++ leaf ++ leaf
    serializer.nodesFromBytes(bytesNegative, KL).isFailure shouldBe true
  }

  property("nodesFromBytes rejects invalid balance in proxy node") {
    val leftLabel = Array.fill(hf.DigestSize)(0.toByte)
    val rightLabel = Array.fill(hf.DigestSize)(1.toByte)
    val bytes = Array(2.toByte, 2.toByte) ++ keyBytes(2, KL) ++ leftLabel ++ rightLabel
    serializer.nodesFromBytes(bytes, KL).isFailure shouldBe true

    val bytesNegative = Array(2.toByte, -2.toByte) ++ keyBytes(2, KL) ++ leftLabel ++ rightLabel
    serializer.nodesFromBytes(bytesNegative, KL).isFailure shouldBe true
  }

  property("nodesFromBytes rejects trailing bytes in internal node") {
    // Use a fixed-size proxy node as the right child so trailing bytes cannot be absorbed as leaf value.
    val leftLeaf = Array(0.toByte) ++ keyBytes(0, KL) ++ keyBytes(1, KL) ++ Array(0.toByte)
    val leftLabel = Array.fill(hf.DigestSize)(0.toByte)
    val rightLabel = Array.fill(hf.DigestSize)(1.toByte)
    val rightProxy = Array(2.toByte, 0.toByte) ++ keyBytes(1, KL) ++ leftLabel ++ rightLabel
    val leftLength = leftLeaf.length
    val internal = Array(1.toByte, 0.toByte) ++ keyBytes(1, KL) ++ Ints.toByteArray(leftLength) ++ leftLeaf ++ rightProxy
    serializer.nodesFromBytes(internal ++ Array(3.toByte), KL).isFailure shouldBe true
  }

  property("nodesFromBytes rejects trailing bytes in proxy node") {
    val leftLabel = Array.fill(hf.DigestSize)(0.toByte)
    val rightLabel = Array.fill(hf.DigestSize)(1.toByte)
    val proxy = Array(2.toByte, 0.toByte) ++ keyBytes(2, KL) ++ leftLabel ++ rightLabel
    serializer.nodesFromBytes(proxy ++ Array(3.toByte), KL).isFailure shouldBe true
  }

  property("combine rejects duplicate subtree ids") {
    val tree = generateProver()
    val sliced = slice(tree)
    val subtrees = sliced._2
    whenever(subtrees.nonEmpty) {
      val duplicate = subtrees.head
      serializer.combine((sliced._1, subtrees :+ duplicate), tree.keyLength, tree.valueLengthOpt).isFailure shouldBe true
    }
  }

  property("combine rejects missing subtrees") {
    val tree = generateProver()
    val sliced = slice(tree)
    val subtrees = sliced._2
    whenever(subtrees.size > 1) {
      val missingOne = subtrees.tail
      serializer.combine((sliced._1, missingOne), tree.keyLength, tree.valueLengthOpt).isFailure shouldBe true
    }
  }

  property("combine rejects unused subtrees") {
    val tree1 = generateProver(InitialTreeSize, keyOffset = 0)
    val tree2 = generateProver(InitialTreeSize, keyOffset = 100000)
    val sliced1 = slice(tree1)
    val sliced2 = slice(tree2)
    val referencedIds = sliced1._1.subtreesIds.map(_.toSeq).toSet
    val extra = sliced2._2.head
    whenever(sliced1._2.nonEmpty && sliced2._2.nonEmpty && !referencedIds.contains(extra.id.toSeq)) {
      serializer.combine((sliced1._1, sliced1._2 :+ extra), tree1.keyLength, tree1.valueLengthOpt).isFailure shouldBe true
    }
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
