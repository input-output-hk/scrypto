package scorex.crypto.authds.avltree

import scorex.crypto.encode.Base58
import scorex.crypto.hash.CryptographicHash

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
  val hf: CryptographicHash
  
  var balance: Level

  def leftLabel: Label

  def rightLabel: Label

  def computeLabel: Label = hf(Array(1: Byte) ++ Array(balance.toByte) ++ leftLabel ++ rightLabel)

}

sealed trait ProverNodes extends Node {
  val key: WTKey
}

sealed trait VerifierNodes extends Node

case class LabelOnlyNode (l : Label) extends Node {
  labelOpt = Some(l)
  def computeLabel : Label = l // TODO it doesn't make sense  to have labelOpt and Label stored here
}

case class ProverNode(key: WTKey, private var _left: ProverNodes, private var _right: ProverNodes, private var _balance : Level = 0)
                     (implicit val hf: CryptographicHash)
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

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $balance)"
  }

}
/*

object VerifierNode {

  def apply(leftLabel: Label, rightLabel: Label, balance: Level)(implicit hf: CryptographicHash): VerifierNode = {
    new VerifierNode(Some(leftLabel), Some(rightLabel), balance, None, None)
  }

  def apply(left: VerifierNodes, right: VerifierNodes, balance: Level)(implicit hf: CryptographicHash): VerifierNode = {
    new VerifierNode(None, None, balance, Some(left), Some(right))
  }

}

class VerifierNode(private var _leftLabel: Option[Label], private var _rightLabel: Option[Label], private val balance: Level,
                   private var _left: Option[VerifierNodes], private var _right: Option[VerifierNodes])
                  (implicit val hf: CryptographicHash) extends VerifierNodes with InternalNode {

  require(_leftLabel.isDefined || left.isDefined) // TODO: this should be XOR rather than OR -- else you have ambiguity 
  require(_rightLabel.isDefined || right.isDefined) // TODO: this should be XOR rather than OR -- else you have ambiguity 

  def leftLabel: Label = _leftLabel.getOrElse(left.get.label)

  def rightLabel: Label = _rightLabel.getOrElse(right.get.label)

  def left: VerifierNodes = _left.get // TODO: is this correct?

  def right: VerifierNodes = _right.get // TODO: is this correct?

  def balance: Level = _balance 

  def leftLabel_=(newLeft: Label) = {
    _leftLabel = Some(newLeft)
    _left = None
    labelOpt = None
  }

  def rightLabel_=(newRight: Label) = {
    _rightLabel = Some(newRight)
    _right = None
    labelOpt = None
  }


  def left_=(newLeft: ProverNodes) = {
    _left = newLeft
    _leftLabel = None
    labelOpt = None
  }

  def right_=(newRight: ProverNodes) = {
    _right = newRight
    _rightLabel = None
    labelOpt = None
  }

  def balance_=(balance: Level) = { TODO: change type
    _balance = balance
    labelOpt = None
  }

*/

case class VerifierNode(private var _left: Node, private var _right: Node, private var _balance: Level)
                  (implicit val hf: CryptographicHash) extends VerifierNodes with InternalNode {

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

case class Leaf(key: WTKey, private var _value: WTValue, private var _nextLeafKey: WTKey)
               (implicit hf: CryptographicHash) extends ProverNodes with VerifierNodes {

  def value: WTValue = _value

  def value_=(newValue: WTValue) = {
    _value = newValue
    labelOpt = None
  }

  def nextLeafKey: WTKey = _nextLeafKey

  def nextLeafKey_=(newNextLeafKey: WTValue) = {
    _nextLeafKey = newNextLeafKey
    labelOpt = None
  }


  def computeLabel: Label = hf(Array(0: Byte) ++ key ++ value ++ nextLeafKey)

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}
