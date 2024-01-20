package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.hash.Digest

import scala.collection.mutable


/**
  * A subtree of AVL tree, which is starting from root node and ending at certain depth with nodes
  * having no children (ProxyInternalNode). The manifest commits to subtrees below the depth.
  */
case class BatchAVLProverManifest[D <: Digest](root: ProverNodes[D], rootHeight: Int) {

  /**
    * Unique (and cryptographically strong) identifier of the manifest (digest of the root node)
    */
  def id: D = root.label

  /**
    * Verify that manifest corresponds to expected digest and height provided by a trusted party
    * (for blockchain protocols, it can be digest and height included by a miner)
    */
  def verify(expectedDigest: D, expectedHeight: Int): Boolean = {
    id.value.sameElements(expectedDigest.value) && expectedHeight == rootHeight
  }

  /**
    * Identifiers (digests) of subtrees below the manifest
    */
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
