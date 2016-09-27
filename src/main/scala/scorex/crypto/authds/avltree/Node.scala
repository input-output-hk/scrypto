package scorex.crypto.authds.avltree

import scorex.crypto.encode.Base58
import scorex.crypto.hash.ThreadUnsafeHash

// TODO: change the type Level everywhere
// TODO: move some common things into InternalNode

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

trait InternalNode {
  val hf: ThreadUnsafeHash

  var balance: Level

  def leftLabel: Label

  def rightLabel: Label

  def computeLabel: Label = hf.prefixedHash(1: Byte, Array(balance.toByte), leftLabel, rightLabel)

}

sealed trait ProverNodes extends Node {
  val key: AVLKey
  var height: Int

  //TODO: needed for debug only
  def printTree() // TODO: needed for debug only
}

sealed trait VerifierNodes extends Node

case class LabelOnlyNode(l: Label) extends Node {
  labelOpt = Some(l)

  def computeLabel: Label = l // TODO it doesn't make sense  to have labelOpt and Label stored here
}

case class ProverNode(key: AVLKey, private var _left: ProverNodes, private var _right: ProverNodes, private var _balance: Level = 0)
                     (implicit val hf: ThreadUnsafeHash)
  extends ProverNodes with InternalNode {

  def left: ProverNodes = _left

  def right: ProverNodes = _right

  def balance: Level = _balance

  def left_=(newLeft: ProverNodes) = {
    _left = newLeft
    labelOpt = None
  }

  def right_=(newRight: ProverNodes) = {
    _right = newRight
    labelOpt = None
  }

  def balance_=(balance: Level) = {
    _balance = balance
    labelOpt = None
  }


  def rightLabel: Label = right.label

  def leftLabel: Label = left.label

  var height = 1

  //TODO: needed for debug only
  def checkHeight: Boolean = {
    height = math.max(right.height, left.height) + 1
    balance == right.height - left.height && balance >= -1 && balance <= 1
  }

  def printTree() = {
    // TODO: needed for debug only
    print(key(0))
    print(" ")
    print(balance)
    print(" L: ")
    left.printTree()
    print(" R: ")
    right.printTree()
  }


  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $balance)"
  }

}

case class VerifierNode(private var _left: Node, private var _right: Node, private var _balance: Level)
                       (implicit val hf: ThreadUnsafeHash) extends VerifierNodes with InternalNode {

  def balance: Level = _balance

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

  def balance_=(balance: Level) = {
    _balance = balance
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

  var height = 0 //TODO: needed for debug only

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

  def printTree() = {
    print(key(0))
    print(" at leaf ")
  } // TODO needed for debug only

  def computeLabel: Label = hf.prefixedHash(0: Byte, key, value, nextLeafKey)

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}
