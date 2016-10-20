package scorex.crypto.authds.avltree

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.encode.Base58
import scorex.crypto.hash.ThreadUnsafeHash

sealed trait Node {

  def computeLabel: Label

  protected def arrayToString(a: Array[Byte]): String = Base58.encode(a).take(8)

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

trait InternalNode extends Node {
  val hf: ThreadUnsafeHash

  protected var _balance: Balance

  def balance: Balance = _balance

  def balance_=(balance: Balance) = {
    _balance = balance
    labelOpt = None
  }

  def leftLabel: Label

  def rightLabel: Label

  def computeLabel: Label = hf.prefixedHash(1: Byte, Array(balance), leftLabel, rightLabel)

}

sealed trait ProverNodes extends Node {
  val key: AVLKey
  protected[avltree] var height: Int
  var isNew: Boolean = true
  var visited: Boolean = false
}

sealed trait VerifierNodes extends Node

case class LabelOnlyNode(l: Label) extends Node {
  labelOpt = Some(l)

  def computeLabel: Label = l // TODO it doesn't make sense  to have labelOpt and Label stored here
}

case class ProverNode(key: AVLKey, private var _left: ProverNodes, private var _right: ProverNodes,
                      protected var _balance: Balance = 0)(implicit val hf: ThreadUnsafeHash)
  extends ProverNodes with InternalNode {

  def left: ProverNodes = _left

  def right: ProverNodes = _right
  
  def left_=(newLeft: ProverNodes) = {
    _left = newLeft
    labelOpt = None
  }
  
  def changeLeft(newLeft: ProverNodes, newBalance: Byte, newNodes: scala.collection.mutable.Buffer[ProverNodes]) : ProverNode = {
    if (isNew) {
      _left = newLeft
      _balance = newBalance
      labelOpt = None
      this
    } else {
      val ret = new ProverNode(this.key, newLeft, this.right, newBalance)
      newNodes += ret
      ret
    }
  }
            
  def right_=(newRight: ProverNodes) = {
    _right = newRight
    labelOpt = None
  }
  
  def changeRight(newRight: ProverNodes, newBalance: Byte, newNodes: scala.collection.mutable.Buffer[ProverNodes]) : ProverNode = {
    if (isNew) {
      _right = newRight
      _balance = newBalance
      labelOpt = None
      this
    } else {
      val ret = new ProverNode(this.key, this.left, newRight, newBalance)
      newNodes += ret
      ret
    }
  }

  def rightLabel: Label = right.label

  def leftLabel: Label = left.label

  var height = 1

  //needed for debug only
  private[avltree] def checkHeight: Boolean = {
    height = math.max(right.height, left.height) + 1
    balance == right.height - left.height && balance >= -1 && balance <= 1
  }

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(leftLabel)}, " +
      "${arrayToString(rightLabel)}, $balance)"
  }

}

case class VerifierNode(private var _left: Node, private var _right: Node, protected var _balance: Balance)
                       (implicit val hf: ThreadUnsafeHash) extends VerifierNodes with InternalNode {

  def left: Node = _left

  def right: Node = _right

  def left_=(newLeft: Node) = {
    _left = newLeft
    labelOpt = None
  }

  def right_=(newRight: Node) = {
    _right = newRight
    labelOpt = None
  }


  def rightLabel: Label = right.label

  def leftLabel: Label = left.label


  override def toString: String = {
    s"${arrayToString(label)}: VerifierNode(${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $balance)"
  }

}

case class Leaf(key: AVLKey, private var _value: AVLValue, private var _nextLeafKey: AVLKey)
               (implicit val hf: ThreadUnsafeHash) extends ProverNodes with VerifierNodes {

  protected[avltree] var height = 0 //needed for debug only

  def value: AVLValue = _value

  def value_=(newValue: AVLValue) = {
    _value = newValue
    labelOpt = None
  }

  def nextLeafKey: AVLKey = _nextLeafKey

  def nextLeafKey_=(newNextLeafKey: AVLValue) = {
    _nextLeafKey = newNextLeafKey
    labelOpt = None
  }

  def changeValue(newValue: AVLValue, newNodes: scala.collection.mutable.Buffer[ProverNodes]) : Leaf = {
    if (isNew) {
      _value = newValue
      labelOpt = None
      this
    } else {
      val ret = new Leaf(this.key, newValue, this.nextLeafKey)
      newNodes += ret
      ret
    }
  }


  def changeNextKey(newNextLeafKey: AVLKey, newNodes: scala.collection.mutable.Buffer[ProverNodes]) : Leaf = {
    if (isNew) {
      _nextLeafKey = newNextLeafKey
      labelOpt = None
      this
    } else {
      val ret = new Leaf(this.key, this.value, newNextLeafKey)
      newNodes += ret
      ret
    }
  }

  def computeLabel: Label = hf.prefixedHash(0: Byte, key, value, nextLeafKey)

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}
