package scorex.crypto.authds.legacy.avltree

import scorex.crypto.authds.avltree.batch.ToStringHelper
import scorex.crypto.authds.{ADKey, ADValue, Balance}
import scorex.crypto.hash._

sealed trait Node extends ToStringHelper {

  def computeLabel: Digest

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

trait InternalNode extends Node {
  val hf: CryptographicHash[_ <: Digest]

  protected var _balance: Balance

  def balance: Balance = _balance

  def balance_=(balance: Balance) = {
    _balance = balance
    labelOpt = None
  }

  def leftLabel: Digest

  def rightLabel: Digest

  def computeLabel: Digest = hf.prefixedHash(1: Byte, Array(balance), leftLabel, rightLabel)

}

sealed trait ProverNodes extends Node {
  val key: ADKey
  protected[avltree] var height: Int
  var isNew: Boolean = true
  var visited: Boolean = false
}

sealed trait VerifierNodes extends Node

case class LabelOnlyNode(l: Digest) extends Node {
  override val computeLabel: Digest = l
  override val label: Digest = l
}

case class ProverNode(key: ADKey, private var _left: ProverNodes, private var _right: ProverNodes,
                      protected var _balance: Balance = Balance @@ 0.toByte)
                     (implicit val hf: CryptographicHash[_ <: Digest]) extends ProverNodes with InternalNode {

  def left: ProverNodes = _left

  def right: ProverNodes = _right

  def left_=(newLeft: ProverNodes) = {
    _left = newLeft
    labelOpt = None
  }

  def right_=(newRight: ProverNodes) = {
    _right = newRight
    labelOpt = None
  }

  def rightLabel: Digest = right.label

  def leftLabel: Digest = left.label

  var height = 1

  //needed for debug only
  private[avltree] def checkHeight: Boolean = {
    height = math.max(right.height, left.height) + 1
    balance == right.height - left.height && balance >= -1 && balance <= 1
  }

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(leftLabel)}, " +
      s"${arrayToString(rightLabel)}, $balance)"
  }

}

case class VerifierNode(private var _left: Node, private var _right: Node, protected var _balance: Balance)
                       (implicit val hf: CryptographicHash[_ <: Digest]) extends VerifierNodes with InternalNode {

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


  def rightLabel: Digest = right.label

  def leftLabel: Digest = left.label


  override def toString: String = {
    s"${arrayToString(label)}: VerifierNode(${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $balance)"
  }

}

case class Leaf(key: ADKey, private var _value: ADValue, private var _nextLeafKey: ADKey)
               (implicit val hf: CryptographicHash[_ <: Digest]) extends ProverNodes with VerifierNodes {


  protected[avltree] var height = 0 //needed for debug only

  def value: ADValue = _value

  def value_=(newValue: ADValue) = {
    _value = newValue
    labelOpt = None
  }

  def nextLeafKey: ADKey = _nextLeafKey

  def nextLeafKey_=(newNextLeafKey: ADKey) = {
    _nextLeafKey = newNextLeafKey
    labelOpt = None
  }

  def computeLabel: Digest = hf.prefixedHash(0: Byte, key, value, nextLeafKey)

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}
