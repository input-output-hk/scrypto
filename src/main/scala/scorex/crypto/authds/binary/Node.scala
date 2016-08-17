package scorex.crypto.authds.binary

import com.google.common.primitives.Ints
import scorex.crypto.authds.binary.Node._
import scorex.crypto.hash.CryptographicHash

trait Node {

  val label: Label

  def label(n: Option[Node]): Label = n.map(_.label).getOrElse(Array())

  def computeLabel: Label
}

object Node {
  type Label = CryptographicHash#Digest
}

case class NonEmptyNode(elem: BTElement, level: Int, left: Option[Node], right: Option[Node], label: Label)
  extends Node {

  override def computeLabel: Label = Hash(elem.bytes ++ Ints.toByteArray(level) ++ label(left) ++ label(right))
}

case class FlatNode[A](elem: BTElement, level: Int, left: Label, right: Label, label: Label) extends Node {
  override def computeLabel: Label = Hash(elem.bytes ++ Ints.toByteArray(level) ++ left ++ right)
}

