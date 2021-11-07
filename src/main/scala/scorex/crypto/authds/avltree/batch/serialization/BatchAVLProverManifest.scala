package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.hash.Digest

import scala.collection.mutable


/**
  * Top subtree of AVL tree, starting from root node and ending with ProxyInternalNode
  */
case class BatchAVLProverManifest[D <: Digest](root: ProverNodes[D], rootHeight: Int) {

  def verify(expectedDigest: D): Boolean = {
    root.label.sameElements(expectedDigest)
  }

  def subtreesIds: mutable.Buffer[D] = {
    def idCollector(node: ProverNodes[D], acc: mutable.Buffer[D]): mutable.Buffer[D] = {
      node match {
        case n: ProxyInternalNode[D] if n.isEmpty =>
          (acc += n.leftLabel) += n.rightLabel
        case i : InternalProverNode[D] =>
          idCollector(i.right, idCollector(i.left, acc))
        case _: ProverLeaf[D] =>
          acc
      }
    }

    idCollector(root, mutable.Buffer.empty)
  }

}
