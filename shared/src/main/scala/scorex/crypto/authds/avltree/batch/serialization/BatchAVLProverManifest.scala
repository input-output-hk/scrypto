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
    *
    * Node labels do not commit to the keys of internal nodes, so matching the digest is not enough on its
    * own. A manifest ends at nodes whose children are only labels, so the keys below it are not available
    * yet and only the search-tree ordering of its own keys can be checked here; the complete check runs on
    * the assembled tree in `BatchAVLProverSerializer.combine`.
    */
  def verify(expectedDigest: D, expectedHeight: Int): Boolean = {
    id.sameElements(expectedDigest) && expectedHeight == rootHeight && NodeKeyChecks.keysAreOrdered(root)
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
