package scorex.crypto.authds.binary

import com.google.common.primitives.Ints
import scorex.crypto.authds.binary.SLTree._

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

case class FlatNode(key: SLTKey, value: SLTKey, level: Int, left: Label, right: Label, label: Label) extends NodeI {
  override def computeLabel: Label = Hash(key ++ value ++ Ints.toByteArray(level) ++ left ++ right)
}

