package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.{BatchAVLProver, InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CryptographicHash, Digest}

import scala.util.Try

class BatchAVLProverSerializer[D <: Digest, HF <: CryptographicHash[D]](implicit val hf: HF) {

  type SlicedTree = (BatchAVLProverManifest[D, HF], Seq[BatchAVLProverSubtree[D, HF]])

  /**
    * Slice AVL tree to top subtree tree (BatchAVLProverManifest) and bottom subtrees (BatchAVLProverSubtree)
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
            parent.mutate(n)
            val leftSubtrees = getSubtrees(n.left, currentHeight - 1, ProxyInternalNode(n))
            val rightSubtrees = getSubtrees(n.right, currentHeight - 1, ProxyInternalNode(n))
            leftSubtrees ++ rightSubtrees
          case n: InternalProverNode[D] =>
            Seq(BatchAVLProverSubtree(n))
          case l: ProverLeaf[D] => Seq(BatchAVLProverSubtree(l))
        }
      }

      val subtrees = getSubtrees(tn.left, height, rootProxyNode) ++ getSubtrees(tn.right, height, rootProxyNode)
      val manifest = BatchAVLProverManifest[D, HF](tree.keyLength, tree.valueLengthOpt, (rootProxyNode, height))
      (manifest, subtrees)
    case l: ProverLeaf[D] =>
      (BatchAVLProverManifest[D, HF](tree.keyLength, tree.valueLengthOpt, (l, tree.rootNodeHeight)), Seq.empty)
  }

  /**
    * Combine tree pieces into one big tree
    */
  def combine(sliced: SlicedTree): Try[BatchAVLProver[D, HF]] = Try {
    sliced._1.oldRootAndHeight._1 match {
      case tn: InternalProverNode[D] =>
        def mutateLoop(n: ProverNodes[D]): Unit = n match {
          case n: ProxyInternalNode[D] if n.isEmty =>
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
        new BatchAVLProver[D, HF](sliced._1.keyLength, sliced._1.valueLengthOpt, Some(sliced._1.oldRootAndHeight))
      case l: ProverLeaf[D] =>
        new BatchAVLProver[D, HF](sliced._1.keyLength, sliced._1.valueLengthOpt, Some(sliced._1.oldRootAndHeight))
    }
  }
}

