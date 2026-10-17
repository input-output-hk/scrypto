package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.ADKey
import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.hash.Digest
import scorex.utils.ByteArray

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
    * (for blockchain protocols, it can be digest and height included by a miner), and that
    * internal node keys (which are not committed to by internal node labels) are strictly increasing
    * in in-order traversal and satisfy AVL balance constraints.
    */
  def verify(expectedDigest: D, expectedHeight: Int): Boolean = {
    id.sameElements(expectedDigest) &&
      expectedHeight == rootHeight &&
      rootHeight >= 0 &&
      BatchAVLProverManifest.verifyNodes(root, rootHeight)
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

object BatchAVLProverManifest {

  private def isFiniteKey(k: ADKey): Boolean = {
    k.nonEmpty && k.exists(_ != 0.toByte) && k.exists(_ != (-1).toByte)
  }

  private[serialization] def verifyNodes[D <: Digest](root: ProverNodes[D], rootHeight: Int): Boolean = {
    var prevInternalKey: Option[ADKey] = None
    var prevLeafNextKey: Option[ADKey] = None

    def loop(node: ProverNodes[D], remainingHeight: Int): Boolean = {
      if (remainingHeight < 0) {
        false
      } else {
        node match {
          case p: ProxyInternalNode[D] if p.isEmpty =>
            val balanceOk = p.balance >= -1 && p.balance <= 1
            val keyFinite = isFiniteKey(p.key)
            val orderOk = prevInternalKey.forall(prev => ByteArray.compare(prev, p.key) < 0)
            val leafLinkOk = prevLeafNextKey.forall(nk => ByteArray.compare(nk, p.key) <= 0)
            if (balanceOk && keyFinite && orderOk && leafLinkOk && remainingHeight > 0) {
              prevInternalKey = Some(p.key)
              prevLeafNextKey = None
              true
            } else {
              false
            }
          case i: InternalProverNode[D] =>
            val balanceOk = i.balance >= -1 && i.balance <= 1
            val keyFinite = isFiniteKey(i.key)
            if (!balanceOk || !keyFinite || remainingHeight <= 0) {
              false
            } else {
              val leftOk = loop(i.left, remainingHeight - 1)
              val orderOk = prevInternalKey.forall(prev => ByteArray.compare(prev, i.key) < 0)
              val leftLeafLinkOk = i.left match {
                case lLeft: ProverLeaf[D] => lLeft.nextLeafKey.sameElements(i.key)
                case _ => prevLeafNextKey.forall(nk => ByteArray.compare(nk, i.key) <= 0)
              }
              val rightLeafLinkOk = i.right match {
                case lRight: ProverLeaf[D] => lRight.key.sameElements(i.key)
                case _ => true
              }
              if (leftOk && orderOk && leftLeafLinkOk && rightLeafLinkOk) {
                prevInternalKey = Some(i.key)
                prevLeafNextKey = None
                loop(i.right, remainingHeight - 1)
              } else {
                false
              }
            }
          case l: ProverLeaf[D] =>
            val leafOrderOk = ByteArray.compare(l.key, l.nextLeafKey) < 0
            val afterPrevInternalOk = prevInternalKey.forall(prev => ByteArray.compare(prev, l.key) <= 0)
            val afterPrevLeafOk = prevLeafNextKey.forall(_.sameElements(l.key))
            if (leafOrderOk && afterPrevInternalOk && afterPrevLeafOk) {
              prevLeafNextKey = Some(l.nextLeafKey)
              true
            } else {
              false
            }
        }
      }
    }

    root match {
      case _: ProverLeaf[D] if rootHeight != 0 => false
      case _ => loop(root, rootHeight)
    }
  }

}
