package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.hash.ThreadUnsafeHash

sealed trait Node extends ToStringHelper {

  var visited: Boolean = false

  protected def computeLabel: Label

  protected var labelOpt: Option[Label] = None

  def label: Label = labelOpt match {
    case None =>
      val l = computeLabel
      labelOpt = Some(l)
      l
    case Some(l) =>
      l
  }
}

sealed trait ProverNodes extends Node {
  var isNew: Boolean = true
  protected var k: AVLKey

  def key: AVLKey = k
}

sealed trait VerifierNodes extends Node

class LabelOnlyNode(l: Label) extends VerifierNodes {
  labelOpt = Some(l)

  protected def computeLabel: Label = l
}

sealed trait InternalNode extends Node {
  protected var b: Balance

  protected val hf: ThreadUnsafeHash

  protected def computeLabel: Label = hf.prefixedHash(1: Byte, Array(b), left.label, right.label)

  def balance: Balance = b

  def left: Node

  def right: Node

  /* These two method may either mutate the existing node or create a new one */
  def getNew(newLeft: Node = left, newRight: Node = right, newBalance: Balance = b): InternalNode

  def getNewKey(newKey: AVLKey): InternalNode
}

class InternalProverNode(protected var k: AVLKey, protected var l: ProverNodes, protected var r: ProverNodes,
                         protected var b: Balance = 0.toByte)(implicit val hf: ThreadUnsafeHash)
  extends ProverNodes with InternalNode {


  override def left: ProverNodes = l.asInstanceOf[ProverNodes]

  override def right: ProverNodes = r.asInstanceOf[ProverNodes]

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNewKey(newKey: AVLKey): InternalProverNode = {
    if (isNew) {
      k = newKey // label doesn't change when key of an internal node changes
      this
    } else {
      val ret = new InternalProverNode(newKey, l, r, b)
      ret.labelOpt = labelOpt // label doesn't change when key of an internal node changes
      ret
    }
  }

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newLeft: Node = l, newRight: Node = r, newBalance: Balance = b): InternalProverNode = {
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
                          (implicit val hf: ThreadUnsafeHash) extends VerifierNodes with InternalNode {


  override def left: Node = l

  override def right: Node = r

  def getNewKey(newKey: AVLKey): InternalNode = {
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

sealed trait Leaf extends Node {
  protected var k: AVLKey
  protected var nk: AVLKey
  protected var v: AVLValue

  def key: AVLKey = k

  def nextLeafKey: AVLKey = nk

  def value: AVLValue = v

  protected val hf: ThreadUnsafeHash // TODO: Seems very wasteful to store hf in every node of the tree, when they are all the same. Is there a better way? Pass them in to label method from above? Same for InternalNode and for other, non-batch, trees

  protected def computeLabel: Label = hf.prefixedHash(0: Byte, k, v, nk)

  def getNew(newKey: AVLKey = k, newValue: AVLValue = v, newNextLeafKey: AVLKey = nk): Leaf

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}

class VerifierLeaf(protected var k: AVLKey, protected var v: AVLValue, protected var nk: AVLKey)
                  (implicit val hf: ThreadUnsafeHash) extends Leaf with VerifierNodes {

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newKey: AVLKey = k, newValue: AVLValue = v, newNextLeafKey: AVLKey = nk): VerifierLeaf = {
    k = newKey
    v = newValue
    nk = newNextLeafKey
    labelOpt = None
    this
  }
}

class ProverLeaf(protected var k: AVLKey, protected var v: AVLValue, protected var nk: AVLKey)
                (implicit val hf: ThreadUnsafeHash) extends Leaf with ProverNodes {

  override def key = k // TODO: we inherit definition of key from two places -- is this the right way to handle it?

  /* This method will mutate the existing node if isNew = true; else create a new one */
  def getNew(newKey: AVLKey = k, newValue: AVLValue = v, newNextLeafKey: AVLKey = nk): ProverLeaf = {
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


