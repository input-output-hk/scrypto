package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverNodes}
import scorex.crypto.authds.{ADKey, Balance}
import scorex.crypto.hash.{CryptographicHash, Digest}

class ProxyInternalNode[D <: Digest](protected var pk: ADKey,
                                     val selfLabelOpt: Option[D],
                                     val leftLabel: D,
                                     val rightLabel: D,
                                     protected var pb: Balance)
                                    (implicit val phf: CryptographicHash[D])
  extends InternalProverNode(k = pk, l = null, r = null, b = pb)(phf) {

  override def computeLabel: D = hf.prefixedHash(1: Byte, Array(b), leftLabel, rightLabel)

  override def label: D = if (isEmpty) selfLabelOpt.getOrElse(computeLabel) else super.label

  def mutate(n: ProverNodes[D]): Unit = {
    if (n.label sameElements leftLabel) {
      l = n
    } else if (n.label sameElements rightLabel) {
      r = n
    } else {
      throw new AssertionError("Unable to determine direction to mutate")
    }
  }

  def isEmpty: Boolean = l == null || r == null

  override def toString: String = s"${arrayToString(label)} ProxyInternalNode($isEmpty,${arrayToString(pk)},${arrayToString(leftLabel)}|${l == null},${arrayToString(rightLabel)}}|${r == null},$pb})"
}

object ProxyInternalNode {
  def apply[D <: Digest](node: InternalProverNode[D])(implicit phf: CryptographicHash[D]): ProxyInternalNode[D] = {
    new ProxyInternalNode[D](node.key, Some(node.label), node.left.label, node.right.label, node.balance)
  }
}
