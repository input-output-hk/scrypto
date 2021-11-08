package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.ADValue
import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.hash.Digest

import scala.collection.mutable

/**
  * AVL subtree, starting from manifest's terminal internal nodes and ending with Leafs
  */
case class BatchAVLProverSubtree[D <: Digest](subtreeTop: ProverNodes[D]) {
  /**
    * Unique (and cryptographically strong) identifier of the sub-tree
    */
  def id: D = subtreeTop.label

  def verify(expectedDigest: D): Boolean = {
    subtreeTop.label.sameElements(expectedDigest)
  }

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