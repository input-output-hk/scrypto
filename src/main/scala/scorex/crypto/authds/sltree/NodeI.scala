package scorex.crypto.authds.sltree

import scorex.crypto.authds.Level
import scorex.crypto.encode.Base58
import scorex.crypto.hash.ThreadUnsafeHash

abstract class NodeI(Hash: ThreadUnsafeHash) {

  protected def label(n: Option[NodeI]): Label = n.map(_.label).getOrElse(LabelOfNone)

  def label: Label

  val key: SLTKey
  var value: SLTValue
  var level: Level

  def leftLabel: Label

  def rightLabel: Label

  def computeLabel: Label = Hash.hash(key, value, level.bytes, leftLabel, rightLabel)

  override def toString: String = {
    Base58.encode(key).take(8) + "|" + Base58.encode(value).take(8) + "|" + level + "|" +
      Base58.encode(leftLabel).take(8) + "|" + Base58.encode(rightLabel).take(8) + "|" + Base58.encode(label).take(8)
  }

}

class Node(val key: SLTKey, var value: SLTKey, var level: Level, var left: Option[Node], var right: Option[Node],
           var label: Label)(implicit hf: ThreadUnsafeHash) extends NodeI(hf) {

  override def leftLabel: Label = label(left)

  override def rightLabel: Label = label(right)

}

class FlatNode(val key: SLTKey, var value: SLTKey, var level: Level, var leftLabel: Label, var rightLabel: Label,
               val labelOpt: Option[Label])(implicit hf: ThreadUnsafeHash) extends NodeI(hf) {

  lazy val label = labelOpt.getOrElse(computeLabel)
}

