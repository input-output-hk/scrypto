package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.ADValue
import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.hash.Digest

import scala.collection.mutable

/**
  * AVL subtree, starting from a manifest's terminal internal node and ending with Leafs
  */
case class BatchAVLProverSubtree[D <: Digest](subtreeTop: ProverNodes[D]) {
  /**
    * Unique (and cryptographically strong) identifier of the sub-tree
    */
  def id: D = subtreeTop.label

  /**
    * Verify that manifest corresponds to expected digest (e.g. got from a manifest)
    *
    * Node labels do not commit to the keys of internal nodes, so matching the digest is not enough on its
    * own: the keys are checked against the ones the leaves imply. A subtree is fully materialized, so that
    * check is complete here.
    */
  def verify(expectedDigest: D): Boolean = {
    subtreeTop.label.sameElements(expectedDigest) && NodeKeyChecks.keysAreConsistent(subtreeTop)
  }

  /**
    * @return leafs of the subtree
    */
  def leafValues: mutable.Buffer[ADValue] = {
    def idCollector(node: ProverNodes[D], acc: mutable.Buffer[ADValue]): mutable.Buffer[ADValue] = {
      node match {
        case i : InternalProverNode[D] =>
          idCollector(i.right, idCollector(i.left, acc))
        case l: ProverLeaf[D] =>
          acc += l.value
      }
    }

    idCollector(subtreeTop, mutable.Buffer.empty)
  }

}