package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.ProverNodes
import scorex.crypto.hash.Digest

/**
  * AVL subtree, starting from manifest's terminal internal nodes and ending with Leafs
  */
case class BatchAVLProverSubtree[D <: Digest](subtreeTop: ProverNodes[D]) {
  /**
    * Unique (and cryptographically strong) identifier of the sub-tree
    */
  def id: D = subtreeTop.label
}