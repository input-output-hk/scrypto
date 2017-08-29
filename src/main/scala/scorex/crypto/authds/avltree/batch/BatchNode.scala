package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.{ADKey, ADValue, Balance}
import scorex.crypto.hash._

sealed trait Node extends ToStringHelper {

  var visited: Boolean = false

  protected def computeLabel: Digest

  protected var labelOpt: Option[Digest] = None

  def label: Digest = labelOpt match {
    case None =>
      val l = computeLabel
      labelOpt = Some(l)
      l
    case Some(l) =>
      l
  }
}

sealed trait ProverNodes extends Node with KeyInVar {
  var isNew: Boolean = true
}

sealed trait VerifierNodes extends Node

class LabelOnlyNode(l: Digest) extends VerifierNodes {
  labelOpt = Some(l)

  protected def computeLabel: Digest = l
}

sealed trait InternalNode extends Node {
  protected var b: Balance

  protected val hf: ThreadUnsafeHash[_ <: Digest]

  protected def computeLabel: Digest = hf.prefixedHash(1: Byte, Array(b), left.label, right.label)

  def balance: Balance = b

  def left: Node

  def right: Node

  /* These two method may either mutate the existing node or create a new one */
  def getNew(newLeft: Node = left, newRight: Node = right, newBalance: Balance = b): InternalNode

  def getNewKey(newKey: ADKey): InternalNode
}

class InternalProverNode(protected var k: ADKey, protected var l: ProverNodes, protected var r: ProverNodes,
                         protected var b: Balance = Balance @@ 0.toByte)(implicit val hf: ThreadUnsafeHash[_ <: Digest])
  extends ProverNodes with InternalNode {


  override def left: ProverNodes = l

  override def right: ProverNodes = r

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNewKey(newKey: ADKey): InternalProverNode = {
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
  def getNew(newLeft: Node = left, newRight: Node = right, newBalance: Balance = b): InternalProverNode = {
    if (isNew) {
      l = newLeft.asInstanceOf[ProverNodes]
      r = newRight.asInstanceOf[ProverNodes]
      b = newBalance
      labelOpt = None
      this
    } else {
      new InternalProverNode(k, newLeft.asInstanceOf[ProverNodes], newRight.asInstanceOf[ProverNodes], newBalance)
    }
  }

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(left.label)}, " +
      s"${arrayToString(right.label)}, $balance)"
  }
}

class InternalVerifierNode(protected var l: Node, protected var r: Node, protected var b: Balance)
                          (implicit val hf: ThreadUnsafeHash[_ <: Digest]) extends VerifierNodes with InternalNode {


  override def left: Node = l

  override def right: Node = r

  def getNewKey(newKey: ADKey): InternalNode = {
    this
  } // Itnernal Verifier Keys have no keys -- so no-op

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newLeft: Node = l, newRight: Node = r, newBalance: Balance = b): InternalVerifierNode = {
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

sealed trait Leaf extends Node with KeyInVar {
  protected var nk: ADKey
  protected var v: ADValue


  def nextLeafKey: ADKey = nk

  def value: ADValue = v

  protected val hf: ThreadUnsafeHash[_ <: Digest] // TODO: Seems very wasteful to store hf in every node of the tree, when they are all the same. Is there a better way? Pass them in to label method from above? Same for InternalNode and for other, non-batch, trees

  protected def computeLabel: Digest = hf.prefixedHash(0: Byte, k, v, nk)

  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): Leaf

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}

class VerifierLeaf(protected var k: ADKey, protected var v: ADValue, protected var nk: ADKey)
                  (implicit val hf: ThreadUnsafeHash[_ <: Digest]) extends Leaf with VerifierNodes {

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): VerifierLeaf = {
    k = newKey
    v = newValue
    nk = newNextLeafKey
    labelOpt = None
    this
  }
}

class ProverLeaf(protected var k: ADKey, protected var v: ADValue, protected var nk: ADKey)
                (implicit val hf: ThreadUnsafeHash[_ <: Digest]) extends Leaf with ProverNodes {

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newKey: ADKey = k, newValue: ADValue = v, newNextLeafKey: ADKey = nk): ProverLeaf = {
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

