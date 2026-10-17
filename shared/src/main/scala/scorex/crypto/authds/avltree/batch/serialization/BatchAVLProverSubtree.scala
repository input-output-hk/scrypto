package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.ADValue
import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.hash.Digest
import scorex.utils.ByteArray

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
    * Verify that subtree corresponds to expected digest (e.g. got from a manifest)
    * and that all internal node keys (which are not committed to by node labels)
    * match the minimum key of their right subtree and satisfy AVL/BST invariants.
    */
  def verify(expectedDigest: D): Boolean = {
    subtreeTop.label.sameElements(expectedDigest) &&
      BatchAVLProverSubtree.verifyNode(subtreeTop).isDefined
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

object BatchAVLProverSubtree {

  private[serialization] def verifyNode[D <: Digest](
    node: ProverNodes[D]
  ): Option[(ProverLeaf[D], ProverLeaf[D], Int)] = node match {
    case p: ProxyInternalNode[D] if p.isEmpty =>
      None
    case r: InternalProverNode[D] =>
      (verifyNode(r.left), verifyNode(r.right)) match {
        case (Some((minLeft, maxLeft, leftHeight)), Some((minRight, maxRight, rightHeight))) =>
          val leftKeyOk = !r.left.isInstanceOf[InternalProverNode[D]] || ByteArray.compare(r.left.key, r.key) < 0
          val rightKeyOk = !r.right.isInstanceOf[InternalProverNode[D]] || ByteArray.compare(r.right.key, r.key) > 0
          val leavesLinkOk = maxLeft.nextLeafKey.sameElements(minRight.key)
          val internalKeyOk = minRight.key.sameElements(r.key)
          val balanceOk = r.balance >= -1 && r.balance <= 1 && r.balance.toInt == rightHeight - leftHeight
          if (leftKeyOk && rightKeyOk && leavesLinkOk && internalKeyOk && balanceOk) {
            Some((minLeft, maxRight, math.max(leftHeight, rightHeight) + 1))
          } else {
            None
          }
        case _ =>
          None
      }
    case l: ProverLeaf[D] =>
      if (ByteArray.compare(l.key, l.nextLeafKey) < 0) Some((l, l, 0)) else None
  }

}