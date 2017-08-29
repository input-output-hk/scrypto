package scorex.crypto.authds.merkle

import scorex.crypto.encode.Base58
import scorex.crypto.hash._

trait Node {
  def hash: Array[Byte]
}

case class InternalNode(left: Node, right: Node)(implicit val hf: CryptographicHash[_ <: Digest]) extends Node {
  override lazy val hash: Array[Byte] = hf.prefixedHash(MerkleTree.InternalNodePrefix, left.hash, right.hash)

  override def toString: String = s"InternalNode(" +
    s"left: ${Base58.encode(left.hash)}, " +
    s"right: ${Base58.encode(right.hash)}," +
    s"hash: ${Base58.encode(hash)})"
}

case class Leaf(data: Array[Byte])(implicit val hf: CryptographicHash[_ <: Digest]) extends Node {
  override lazy val hash: Array[Byte] = hf.prefixedHash(MerkleTree.LeafPrefix, data)

  override def toString: String = s"Leaf(${Base58.encode(hash)})"
}

case object EmptyNode extends Node {
  override val hash: Array[Byte] = Array[Byte]()
}
