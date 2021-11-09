package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.InternalNode.InternalNodePrefix
import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverNodes}
import scorex.crypto.authds.{ADKey, Balance}
import scorex.crypto.hash.{CryptographicHash, Digest}

/**
  * Internal node for which not children are stored but just their digests
  */
class ProxyInternalNode[D <: Digest](protected var pk: ADKey,
                                     val selfLabelOpt: Option[D],
                                     val leftLabel: D,
                                     val rightLabel: D,
                                     protected var pb: Balance)
                                    (implicit val phf: CryptographicHash[D])
  extends InternalProverNode(k = pk, l = null, r = null, b = pb)(phf) {

  override def computeLabel: D = {
    hf.hash(Array(InternalNodePrefix, b), leftLabel, rightLabel)
  }

  /**
    * Get digest of the node. If it was computed previously, read the digest from hash, otherwise,
    * take externally provided label or compute if not provided.
    */
  override def label: D = labelOpt match {
    case Some(l) =>
      l
    case None =>
      val l = selfLabelOpt.getOrElse(computeLabel)
      labelOpt = Some(l)
      l
  }

  private[serialization] def setChild(n: ProverNodes[D]): Unit = {
    if (n.label sameElements leftLabel) {
      l = n
    } else if (n.label sameElements rightLabel) {
      r = n
    } else {
      throw new AssertionError("Unable to determine direction to mutate")
    }
  }

  def isEmpty: Boolean = l == null || r == null

  override def toString: String = {
    s"${arrayToString(label)} ProxyInternalNode($isEmpty,${arrayToString(pk)},${arrayToString(leftLabel)}|${l == null},${arrayToString(rightLabel)}}|${r == null},$pb})"
  }

}

object ProxyInternalNode {
  def apply[D <: Digest](node: InternalProverNode[D])(implicit phf: CryptographicHash[D]): ProxyInternalNode[D] = {
    new ProxyInternalNode[D](node.key, Some(node.label), node.left.label, node.right.label, node.balance)
  }
}
