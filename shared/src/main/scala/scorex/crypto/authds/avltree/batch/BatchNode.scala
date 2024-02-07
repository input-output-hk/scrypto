package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds._
import scorex.crypto.hash._

sealed trait Node[D <: Digest] extends ToStringHelper {

  var visited: Boolean = false

  protected def computeLabel: D

  protected var labelOpt: Option[D] = None

  /**
    * Get digest of the node. If it was computed previously, read the digest from hash, otherwise, compute it.
    */
  def label: D = labelOpt match {
    case None =>
      val l = computeLabel
      labelOpt = Some(l)
      l
    case Some(l) =>
      l
  }
}

sealed trait ProverNodes[D <: Digest] extends Node[D] with KeyInVar {
  var isNew: Boolean = true
}

sealed trait VerifierNodes[D <: Digest] extends Node[D]

class LabelOnlyNode[D <: Digest](l: D) extends VerifierNodes[D] {
  labelOpt = Some(l)

  protected def computeLabel: D = l
}

sealed trait InternalNode[D <: Digest] extends Node[D] {
  import InternalNode.InternalNodePrefix

  protected var b: Balance

  protected val hf: CryptographicHash[D]

  override protected def computeLabel: D = {
    hf.hash(Array(InternalNodePrefix, b), left.label, right.label)
  }

  def balance: Balance = b

  def left: Node[D]

  def right: Node[D]

  /* These two method may either mutate the existing node or create a new one */
  def getNew(newLeft: Node[D] = left, newRight: Node[D] = right, newBalance: Balance = b): InternalNode[D]

  def getNewKey(newKey: ADKey): InternalNode[D]
}

object InternalNode {
  val InternalNodePrefix: Byte = 1: Byte
}

class InternalProverNode[D <: Digest](protected var k: ADKey,
                                      protected var l: ProverNodes[D],
                                      protected var r: ProverNodes[D],
                                      protected var b: Balance = Balance @@ 0.toByte)(implicit val hf: CryptographicHash[D])
  extends ProverNodes[D] with InternalNode[D] {


  override def left: ProverNodes[D] = l

  override def right: ProverNodes[D] = r

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNewKey(newKey: ADKey): InternalProverNode[D] = {
    if (isNew) {
      k = newKey // label doesn't change when key of an internal node changes
      this
    } else {
      val ret = new InternalProverNode(newKey, left, right, b)
      ret.labelOpt = labelOpt // label doesn't change when key of an internal node changes
      ret
    }
  }

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newLeft: Node[D] = left, newRight: Node[D] = right, newBalance: Balance = b): InternalProverNode[D] = {
    if (isNew) {
      l = newLeft.asInstanceOf[ProverNodes[D]]
      r = newRight.asInstanceOf[ProverNodes[D]]
      b = newBalance
      labelOpt = None
      this
    } else {
      new InternalProverNode(k, newLeft.asInstanceOf[ProverNodes[D]], newRight.asInstanceOf[ProverNodes[D]], newBalance)
    }
  }

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(left.label)}, " +
      s"${arrayToString(right.label)}, $balance)"
  }
}

class InternalVerifierNode[D <: Digest](protected var l: Node[D], protected var r: Node[D], protected var b: Balance)
                                       (implicit val hf: CryptographicHash[D]) extends VerifierNodes[D] with InternalNode[D] {


  override def left: Node[D] = l

  override def right: Node[D] = r

  // Internal Verifier Keys have no keys -- so no-op
  def getNewKey(newKey: ADKey): InternalNode[D] = this

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newLeft: Node[D] = l, newRight: Node[D] = r, newBalance: Balance = b): InternalVerifierNode[D] = {
    l = newLeft
    r = newRight
    b = newBalance
    labelOpt = None
    this
  }

  override def toString: String = {
    s"${arrayToString(label)}: VerifierNode(${arrayToString(left.label)}, ${arrayToString(right.label)}, $balance)"
  }
}

sealed trait Leaf[D <: Digest] extends Node[D] with KeyInVar {
  import Leaf.LeafPrefix

  protected var nk: ADKey
  protected var v: ADValue

  def nextLeafKey: ADKey = nk

  def value: ADValue = v

  protected val hf: CryptographicHash[D] // TODO: Seems very wasteful to store hf in every node of the tree, when they are all the same. Is there a better way? Pass them in to label method from above? Same for InternalNode and for other, non-batch, trees

  protected def computeLabel: D = {
    hf.prefixedHash(LeafPrefix, k, v, nk)
  }

  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): Leaf[D]

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }

}

object Leaf {
  val LeafPrefix = 0: Byte
}

class VerifierLeaf[D <: Digest](protected var k: ADKey, protected var v: ADValue, protected var nk: ADKey)
                               (implicit val hf: CryptographicHash[D]) extends Leaf[D] with VerifierNodes[D] {

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): VerifierLeaf[D] = {
    k = newKey
    v = newValue
    nk = newNextLeafKey
    labelOpt = None
    this
  }
}

class ProverLeaf[D <: Digest](protected var k: ADKey, protected var v: ADValue, protected var nk: ADKey)
                             (implicit val hf: CryptographicHash[D]) extends Leaf[D] with ProverNodes[D] {

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): ProverLeaf[D] = {
    if (isNew) {
      k = newKey
      v = newValue
      nk = newNextLeafKey
      labelOpt = None
      this
    } else {
      new ProverLeaf(newKey, newValue, newNextLeafKey)
    }
  }
}

trait KeyInVar {
  protected var k: ADKey

  def key: ADKey = k
}

