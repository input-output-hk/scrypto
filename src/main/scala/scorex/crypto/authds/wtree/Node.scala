package scorex.crypto.authds.wtree

import scorex.crypto.encode.Base58
import scorex.crypto.hash.CryptographicHash

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
  val NotCalculatedLabel: Label = Array()

  var label: Label

  def computeLabel: Label

  val isLeaf: Boolean

  protected def arrayToString(a: Array[Byte]): String = Base58.encode(a).take(8)
}

sealed trait ProverNodes extends Node {
  val key: WTKey
  lazy val level = levelFromKey(key)

  val labelOpt: Option[Label]
  override var label: Label = labelOpt.getOrElse(computeLabel)
}

sealed trait VerifierNodes extends Node

case class ProverNode(key: WTKey, var left: ProverNodes, var right: ProverNodes, labelOpt: Option[Label] = None)
                     (implicit hf: CryptographicHash) extends ProverNodes {


  override def computeLabel: Label = hf(level +: (leftLabel ++ rightLabel))

  override val isLeaf: Boolean = false

  def rightLabel: Label = right.label
  def leftLabel: Label = left.label

  override def toString: String = {
    s"${arrayToString(label)}: ProverNode(${arrayToString(key)}, ${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $level)"
  }

}

case class VerifierNode(var leftLabel: Label, var rightLabel: Label, level: Level)
                       (implicit hf: CryptographicHash) extends VerifierNodes {
  var label: Label = computeLabel

  override def computeLabel: Label = hf(level +: (leftLabel ++ rightLabel))

  override val isLeaf: Boolean = false

  override def toString: String = {
    s"${arrayToString(label)}: VerifierNode(${arrayToString(leftLabel)}, ${arrayToString(rightLabel)}, $level)"
  }

}

case class Leaf(key: WTKey, var value: WTValue, var nextLeafKey: WTKey, labelOpt: Option[Label] = None)
               (implicit hf: CryptographicHash) extends ProverNodes with VerifierNodes {

  override def computeLabel: Label = hf(key ++ value ++ nextLeafKey)

  override val isLeaf: Boolean = true

  override def toString: String = {
    s"${arrayToString(label)}: Leaf(${arrayToString(key)}, ${arrayToString(value)}, ${arrayToString(nextLeafKey)})"
  }
}
