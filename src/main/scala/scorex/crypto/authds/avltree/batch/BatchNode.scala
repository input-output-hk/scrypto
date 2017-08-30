package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.{ADKey, ADValue, Balance}
import scorex.crypto.hash._

sealed trait Node[T <: Digest] extends ToStringHelper {

  var visited: Boolean = false

  protected def computeLabel: T

  protected var labelOpt: Option[T] = None

  def label: Digest = labelOpt match {
    case None =>
      val l = computeLabel
      labelOpt = Some(l)
      l
    case Some(l) =>
      l
  }
}

sealed trait ProverNodes[T <: Digest] extends Node[T] with KeyInVar {
  var isNew: Boolean = true
}

sealed trait VerifierNodes[T <: Digest] extends Node[T]

class LabelOnlyNode[T <: Digest](l: T) extends VerifierNodes[T] {
  labelOpt = Some(l)

  protected def computeLabel: T = l
}

sealed trait InternalNode[T <: Digest] extends Node[T] {
  protected var b: Balance

  protected val hf: ThreadUnsafeHash[T]

  protected def computeLabel: T = hf.prefixedHash(1: Byte, Array(b), left.label, right.label)

  def balance: Balance = b

  def left: Node[T]

  def right: Node[T]

  /* These two method may either mutate the existing node or create a new one */
  def getNew(newLeft: Node[T] = left, newRight: Node[T] = right, newBalance: Balance = b): InternalNode[T]

  def getNewKey(newKey: ADKey): InternalNode[T]
}

class InternalProverNode[T <: Digest](protected var k: ADKey,
                                      protected var l: ProverNodes[T],
                                      protected var r: ProverNodes[T],
                         protected var b: Balance = Balance @@ 0.toByte)(implicit val hf: ThreadUnsafeHash[T])
  extends ProverNodes[T] with InternalNode[T] {


  override def left: ProverNodes[T] = l

  override def right: ProverNodes[T] = r

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNewKey(newKey: ADKey): InternalProverNode[T] = {
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
  def getNew(newLeft: Node[T] = left, newRight: Node[T] = right, newBalance: Balance = b): InternalProverNode[T] = {
    if (isNew) {
      l = newLeft.asInstanceOf[ProverNodes[T]]
      r = newRight.asInstanceOf[ProverNodes[T]]
      b = newBalance
      labelOpt = None
      this
    } else {
      new InternalProverNode(k, newLeft.asInstanceOf[ProverNodes[T]], newRight.asInstanceOf[ProverNodes[T]], newBalance)
    }
  }

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(left.label)}, " +
      s"${arrayToString(right.label)}, $balance)"
  }
}

class InternalVerifierNode[T <: Digest](protected var l: Node[T], protected var r: Node[T], protected var b: Balance)
                          (implicit val hf: ThreadUnsafeHash[T]) extends VerifierNodes[T] with InternalNode[T] {


  override def left: Node[T] = l

  override def right: Node[T] = r

  // Internal Verifier Keys have no keys -- so no-op
  def getNewKey(newKey: ADKey): InternalNode[T] = this

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newLeft: Node[T] = l, newRight: Node[T] = r, newBalance: Balance = b): InternalVerifierNode[T] = {
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

sealed trait Leaf[T <: Digest] extends Node[T] with KeyInVar {
  protected var nk: ADKey
  protected var v: ADValue


  def nextLeafKey: ADKey = nk

  def value: ADValue = v

  protected val hf: ThreadUnsafeHash[T] // TODO: Seems very wasteful to store hf in every node of the tree, when they are all the same. Is there a better way? Pass them in to label method from above? Same for InternalNode and for other, non-batch, trees

  protected def computeLabel: T = hf.prefixedHash(0: Byte, k, v, nk)

  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): Leaf[T]

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}

class VerifierLeaf[T <: Digest](protected var k: ADKey, protected var v: ADValue, protected var nk: ADKey)
                  (implicit val hf: ThreadUnsafeHash[T]) extends Leaf[T] with VerifierNodes[T] {

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): VerifierLeaf[T] = {
    k = newKey
    v = newValue
    nk = newNextLeafKey
    labelOpt = None
    this
  }
}

class ProverLeaf[T <: Digest](protected var k: ADKey, protected var v: ADValue, protected var nk: ADKey)
                (implicit val hf: ThreadUnsafeHash[T]) extends Leaf[T] with ProverNodes[T] {

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): ProverLeaf[T] = {
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

