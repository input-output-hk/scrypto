package scorex.crypto.authds.avltree.batch.serialization

import com.google.common.primitives.{Bytes, Ints}
import scorex.crypto.authds.avltree.batch.{BatchAVLProver, InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.authds.{ADKey, ADValue, Balance}
import scorex.crypto.hash.{CryptographicHash, Digest}

import scala.util.Try

class BatchAVLProverSerializer[D <: Digest, HF <: CryptographicHash[D]](implicit val hf: HF) {

  private val labelLength = hf.DigestSize

  type SlicedTree = (BatchAVLProverManifest[D, HF], Seq[BatchAVLProverSubtree[D, HF]])

  def slice(tree: BatchAVLProver[D, HF]): SlicedTree = slice(tree, tree.rootNodeHeight / 2)

  /**
    * Slice AVL tree to top subtree tree (BatchAVLProverManifest) and
    * bottom subtrees (BatchAVLProverSubtree) with height `subtreeDepth`
    */
  def slice(tree: BatchAVLProver[D, HF], subtreeDepth: Int): SlicedTree = tree.topNode match {
    case tn: InternalProverNode[D] =>

      val height = tree.rootNodeHeight
      val rootProxyNode = ProxyInternalNode(tn)

      def getSubtrees(currentNode: ProverNodes[D],
                      currentHeight: Int,
                      parent: ProxyInternalNode[D]): Seq[BatchAVLProverSubtree[D, HF]] = {
        currentNode match {
          case n: InternalProverNode[D] if currentHeight > subtreeDepth =>
            val nextParent = ProxyInternalNode(n)
            parent.mutate(nextParent)
            val leftSubtrees = getSubtrees(n.left, currentHeight - 1, nextParent)
            val rightSubtrees = getSubtrees(n.right, currentHeight - 1, nextParent)
            leftSubtrees ++ rightSubtrees
          case n: InternalProverNode[D] =>
            parent.mutate(ProxyInternalNode(n))
            Seq(BatchAVLProverSubtree(n.left), BatchAVLProverSubtree(n.right))
          case l: ProverLeaf[D] =>
            parent.mutate(l)
            Seq(BatchAVLProverSubtree(l))
        }
      }

      val subtrees = getSubtrees(tn.left, height - 1, rootProxyNode) ++ getSubtrees(tn.right, height - 1, rootProxyNode)
      val manifest = BatchAVLProverManifest[D, HF](tree.keyLength, tree.valueLengthOpt, (rootProxyNode, height))
      (manifest, subtrees)
    case l: ProverLeaf[D] =>
      (BatchAVLProverManifest[D, HF](tree.keyLength, tree.valueLengthOpt, (l, tree.rootNodeHeight)), Seq.empty)
  }

  /**
    * Combine tree pieces into one big tree
    */
  def combine(sliced: SlicedTree): Try[BatchAVLProver[D, HF]] = Try {
    sliced._1.rootAndHeight._1 match {
      case tn: InternalProverNode[D] =>
        def mutateLoop(n: ProverNodes[D]): Unit = n match {
          case n: ProxyInternalNode[D] if n.isEmpty =>
            val left = sliced._2.find(_.subtreeTop.label sameElements n.leftLabel).get.subtreeTop
            val right = sliced._2.find(_.subtreeTop.label sameElements n.rightLabel).get.subtreeTop
            n.mutate(left)
            n.mutate(right)
          case n: InternalProverNode[D] =>
            mutateLoop(n.left)
            mutateLoop(n.right)
          case _ =>
        }

        mutateLoop(tn)
        new BatchAVLProver[D, HF](sliced._1.keyLength, sliced._1.valueLengthOpt, Some(sliced._1.rootAndHeight))
      case _: ProverLeaf[D] =>
        new BatchAVLProver[D, HF](sliced._1.keyLength, sliced._1.valueLengthOpt, Some(sliced._1.rootAndHeight))
    }
  }

  def manifestToBytes(manifest: BatchAVLProverManifest[D, HF]): Array[Byte] = {
    Bytes.concat(Ints.toByteArray(manifest.keyLength),
      Ints.toByteArray(manifest.valueLengthOpt.getOrElse(-1)),
      Ints.toByteArray(manifest.rootAndHeight._2),
      nodesToBytes(manifest.rootAndHeight._1)
    )
  }

  def manifestFromBytes(bytes: Array[Byte]): Try[BatchAVLProverManifest[D, HF]] = Try {
    val keyLength = Ints.fromByteArray(bytes.slice(0, 4))
    val valueLength = Ints.fromByteArray(bytes.slice(4, 8))
    if (valueLength < -1) throw new Error(s"Wrong valueLength: $valueLength")
    val valueLengthOpt = if (valueLength == -1) None else Some(valueLength)
    val oldHeight = Ints.fromByteArray(bytes.slice(8, 12))
    val oldTop = nodesFromBytes(bytes.slice(12, bytes.length), keyLength).get
    BatchAVLProverManifest[D, HF](keyLength, valueLengthOpt, (oldTop, oldHeight))
  }

  def subtreeToBytes(t: BatchAVLProverSubtree[D, HF]): Array[Byte] = nodesToBytes(t.subtreeTop)

  def subtreeFromBytes(b: Array[Byte], kl: Int): Try[BatchAVLProverSubtree[D, HF]] = nodesFromBytes(b, kl).
    map(topNode => BatchAVLProverSubtree[D, HF](topNode))

  def nodesToBytes(obj: ProverNodes[D]): Array[Byte] = {
    def loop(currentNode: ProverNodes[D]): Array[Byte] = currentNode match {
      case l: ProverLeaf[D] =>
        Bytes.concat(Array(0.toByte), l.key, l.nextLeafKey, l.value)
      case n: ProxyInternalNode[D] if n.isEmpty =>
        Bytes.concat(Array(2.toByte, n.balance), n.key, n.leftLabel, n.rightLabel, n.label)
      case n: InternalProverNode[D] =>
        val leftBytes = loop(n.left)
        val rightBytes = loop(n.right)
        Bytes.concat(Array(1.toByte, n.balance), n.key, Ints.toByteArray(leftBytes.length), leftBytes, rightBytes)
    }

    loop(obj)
  }

  def nodesFromBytes(bytesIn: Array[Byte], keyLength: Int): Try[ProverNodes[D]] = Try {
    def loop(bytes: Array[Byte]): ProverNodes[D] = bytes.head match {
      case 0 =>
        val key = ADKey @@ bytes.slice(1, keyLength + 1)
        val nextLeafKey = ADKey @@ bytes.slice(keyLength + 1, 2 * keyLength + 1)
        val value = ADValue @@ bytes.slice(2 * keyLength + 1, bytes.length)
        new ProverLeaf[D](key, value, nextLeafKey)
      case 1 =>
        val balance = Balance @@ bytes.slice(1, 2).head
        val key = ADKey @@ bytes.slice(2, keyLength + 2)
        val leftLength = Ints.fromByteArray(bytes.slice(keyLength + 2, keyLength + 6))
        val leftBytes = bytes.slice(keyLength + 6, keyLength + 6 + leftLength)
        val rightBytes = bytes.slice(keyLength + 6 + leftLength, bytes.length)
        val left = loop(leftBytes)
        val right = loop(rightBytes)
        new InternalProverNode[D](key, left, right, balance)
      case 2 =>
        val balance = Balance @@ bytes.slice(1, 2).head
        val key = ADKey @@ bytes.slice(2, keyLength + 2)
        val leftLabel = hf.byteArrayToDigest(bytes.slice(keyLength + 2, keyLength + 2 + labelLength)).get
        val rightLabel = hf.byteArrayToDigest(bytes.slice(keyLength + 2 + labelLength, keyLength + 2 + 2 * labelLength)).get
        val selfLabel = hf.byteArrayToDigest(bytes.slice(keyLength + 2 + 2 * labelLength, keyLength + 2 + 3 * labelLength)).get
        new ProxyInternalNode[D](key, Some(selfLabel), leftLabel, rightLabel, balance)
      case _ =>
        ???
    }

    loop(bytesIn)
  }
}

