package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverNodes}
import scorex.crypto.authds.{ADKey, Balance}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CryptographicHash, Digest}

class ProxyInternalNode[D <: Digest](protected var pk: ADKey,
                                     val selfLabel: D,
                                     val leftLabel: D,
                                     val rightLabel: D,
                                     protected var pb: Balance)
                                    (implicit val phf: CryptographicHash[D])
  extends InternalProverNode(k = pk, l = null, r = null, b = pb)(phf) {

  override def label: D = selfLabel

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

  override def toString: String = s"${hashCode()} ProxyInternalNode($isEmpty,${Base58.encode(pk).take(8)},${Base58.encode(leftLabel).take(8)}|${l == null},${Base58.encode(rightLabel).take(8)}}|${r == null},$pb})"
}

object ProxyInternalNode {
  def apply[D <: Digest](node: InternalProverNode[D])(implicit phf: CryptographicHash[D]): ProxyInternalNode[D] = {
    new ProxyInternalNode[D](node.key, node.label, node.left.label, node.right.label, node.balance)
  }
}
