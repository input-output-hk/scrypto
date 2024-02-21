package scorex.crypto.authds.legacy.treap

import scorex.crypto.authds.avltree.batch.ToStringHelper
import scorex.crypto.authds.legacy.treap.Constants.LevelFunction
import scorex.crypto.authds.{ADKey, ADValue}
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

trait InternalNode {
  val hf: CryptographicHash[_ <: Digest]
  def level: Level

  def leftLabel: Digest

  def rightLabel: Digest

  def computeLabel: Digest = hf.prefixedHash(1: Byte, level.bytes, leftLabel, rightLabel)

}

sealed trait ProverNodes extends Node {
  val key: ADKey
}

sealed trait VerifierNodes extends Node

case class ProverNode(key: ADKey, private var _left: ProverNodes, private var _right: ProverNodes)
                     (implicit val hf: CryptographicHash[_ <: Digest], levelFunc: LevelFunction)
  extends ProverNodes with InternalNode {

  def level: Level = levelFunc(key)

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

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $level)"
  }

}

case class VerifierNode(private var _leftLabel: Digest, private var _rightLabel: Digest, level: Level)
                       (implicit val hf: CryptographicHash[_ <: Digest]) extends VerifierNodes with InternalNode {

  def leftLabel: Digest = _leftLabel

  def rightLabel: Digest = _rightLabel

  def leftLabel_=(newLeft: Digest) = {
    _leftLabel = newLeft
    labelOpt = None
  }

  def rightLabel_=(newRight: Digest) = {
    _rightLabel = newRight
    labelOpt = None
  }

  override def toString: String = {
    s"${arrayToString(label)}: VerifierNode(${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $level)"
  }

}

case class Leaf(key: ADKey, private var _value: ADValue, private var _nextLeafKey: ADKey)
               (implicit hf: CryptographicHash[_ <: Digest]) extends ProverNodes with VerifierNodes {

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
