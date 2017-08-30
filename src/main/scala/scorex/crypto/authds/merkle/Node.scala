package scorex.crypto.authds.merkle

import scorex.crypto.authds.LeafData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Digest32, _}

trait Node[T <: Digest] {
  def hash: T
}

case class InternalNode[T <: Digest](left: Node[T], right: Node[T])
                                    (implicit val hf: CryptographicHash[T]) extends Node[T] {

  override lazy val hash: T = hf.prefixedHash(MerkleTree.InternalNodePrefix, left.hash, right.hash)

  override def toString: String = s"InternalNode(" +
    s"left: ${Base58.encode(left.hash)}, " +
    s"right: ${Base58.encode(right.hash)}," +
    s"hash: ${Base58.encode(hash)})"
}

case class Leaf[T <: Digest](data: LeafData)(implicit val hf: CryptographicHash[T]) extends Node[T] {
  override lazy val hash: T = hf.prefixedHash(MerkleTree.LeafPrefix, data)

  override def toString: String = s"Leaf(${Base58.encode(hash)})"
}

case class EmptyNode[T <: Digest]() extends Node[T] {
  override val hash: T = Array[Byte]().asInstanceOf[T]
}
