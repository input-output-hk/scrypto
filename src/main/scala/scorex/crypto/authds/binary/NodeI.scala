package scorex.crypto.authds.binary

import com.google.common.primitives.Ints
import scorex.crypto.encode.Base58

trait NodeI {

  protected def label(n: Option[NodeI]): Label = n.map(_.label).getOrElse(LabelOfNone)

  def label: Label
  val key: SLTKey
  var value: SLTValue
  var level: Int

  def leftLabel: Label

  def rightLabel: Label

  def computeLabel: Label = Hash(key ++ value ++ Ints.toByteArray(level) ++ leftLabel ++ rightLabel)

  override def toString: String = {
    Base58.encode(key).take(8) + "|" + Base58.encode(value).take(8) + "|" + level + "|" +
      Base58.encode(leftLabel).take(8) + "|" + Base58.encode(rightLabel).take(8) + "|" + Base58.encode(label).take(8)
  }

}

class Node(val key: SLTKey, var value: SLTKey, var level: Int, var left: Option[Node], var right: Option[Node],
           var label: Label) extends NodeI {

  override def leftLabel: Label = label(left)

  override def rightLabel: Label = label(right)

}

class FlatNode(val key: SLTKey, var value: SLTKey, var level: Int, var leftLabel: Label, var rightLabel: Label,
               val labelOpt: Option[Label]) extends NodeI {


  def label: Label = labelOpt.getOrElse(computeLabel)

}

