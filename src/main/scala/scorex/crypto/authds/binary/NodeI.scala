package scorex.crypto.authds.binary

import com.google.common.primitives.Ints

trait NodeI {

  def label(n: Option[NodeI]): Label = n.map(_.label).getOrElse(LabelOfNone)

  var label: Label
  val key: SLTKey
  val value: SLTValue
  val level: Int

  def computeLabel: Label
}

class Node(val key: SLTKey, val value: SLTKey, var level: Int, var left: Option[Node], var right: Option[Node],
           var label: Label) extends NodeI {

  override def computeLabel: Label = Hash(key ++ value ++ Ints.toByteArray(level) ++ label(left) ++ label(right))
}

class FlatNode(val key: SLTKey, val value: SLTKey, var level: Int, var leftLabel: Label, var rightLabel: Label,
               val labelOpt: Option[Label]) extends NodeI {


  override var label: Label = labelOpt.getOrElse(computeLabel)

  override def computeLabel: Label = Hash(key ++ value ++ Ints.toByteArray(level) ++ leftLabel ++ rightLabel)
}

