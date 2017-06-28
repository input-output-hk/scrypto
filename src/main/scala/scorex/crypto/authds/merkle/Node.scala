package scorex.crypto.authds.merkle

import scorex.crypto.hash.ThreadUnsafeHash

trait Node {
  def hash: Array[Byte]
}

case class InternalNode(left: Node, right: Node)
                       (implicit val hf: ThreadUnsafeHash) extends Node {
  override lazy val hash: Array[Byte] = right match {
    case EmptyNode => left.hash
    case n: Node => hf.prefixedHash(1: Byte, left.hash, right.hash)
  }
}

case class Leaf(data: Array[Byte])
               (implicit val hf: ThreadUnsafeHash) extends Node {
  override lazy val hash = hf.prefixedHash(0: Byte, data)

}

case object EmptyNode extends Node {
  override val hash: Array[Byte] = Array[Byte]()
}
