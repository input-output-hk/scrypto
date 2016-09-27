package scorex.crypto.authds.wtree

import scorex.crypto.authds.Level
import scorex.crypto.encode.Base58
import scorex.crypto.hash.ThreadUnsafeHash

// WE NEED TO MAKE THE FOLLOWING MODIFICATIONS TO THE DEFINITION OF NODE
// There are two kinds of nodes on the prover side: internal nodes and leaves
// internal nodes always have two children (so no options on right and left)
// leaves always have no children
// internal nodes store a key and a level
// leaves store key, value, and nextLeafKey
// Both have labels (which do not need to be options; we should not compute them at creation time,
// but rather should set them to all 0 or labelOfNone, doesn't matter)
//
//
// There are also two kinds of nodes on the verifier side: flat internal nodes and leaves
// leaves are the same as on the prover side
// flat internal nodes store a level and hashes of the two children. They do NOT store the key.
// Both have labels
//

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
  val level: Level

  def leftLabel: Label

  def rightLabel: Label

  def computeLabel: Label = hf.prefixedHash(1: Byte, level.bytes, leftLabel, rightLabel)

}

sealed trait ProverNodes extends Node {
  val key: WTKey
}

sealed trait VerifierNodes extends Node

case class ProverNode(key: WTKey, private var _left: ProverNodes, private var _right: ProverNodes)
                     (implicit val hf: ThreadUnsafeHash, levelFunc: LevelFunction)
  extends ProverNodes with InternalNode {

  lazy val level = levelFunc(key)

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

  def rightLabel: Label = right.label

  def leftLabel: Label = left.label

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $level)"
  }

}

case class VerifierNode(private var _leftLabel: Label, private var _rightLabel: Label, level: Level)
                       (implicit val hf: ThreadUnsafeHash) extends VerifierNodes with InternalNode {

  def leftLabel: Label = _leftLabel

  def rightLabel: Label = _rightLabel

  def leftLabel_=(newLeft: Label) = {
    _leftLabel = newLeft
    labelOpt = None
  }

  def rightLabel_=(newRight: Label) = {
    _rightLabel = newRight
    labelOpt = None
  }

  override def toString: String = {
    s"${arrayToString(label)}: VerifierNode(${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $level)"
  }

}

case class Leaf(key: WTKey, private var _value: WTValue, private var _nextLeafKey: WTKey)
               (implicit hf: ThreadUnsafeHash) extends ProverNodes with VerifierNodes {

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

  def computeLabel: Label = hf.prefixedHash(0: Byte, key, value, nextLeafKey)

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}
