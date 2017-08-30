package scorex.crypto.authds.merkle

import scorex.crypto.authds.LeafData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Digest32, _}

trait Node[D <: Digest] {
  def hash: D
}

case class InternalNode[D <: Digest](left: Node[D], right: Node[D])
                                    (implicit val hf: CryptographicHash[D]) extends Node[D] {

  override lazy val hash: D = hf.prefixedHash(MerkleTree.InternalNodePrefix, left.hash, right.hash)

  override def toString: String = s"InternalNode(" +
    s"left: ${Base58.encode(left.hash)}, " +
    s"right: ${Base58.encode(right.hash)}," +
    s"hash: ${Base58.encode(hash)})"
}

case class Leaf[D <: Digest](data: LeafData)(implicit val hf: CryptographicHash[D]) extends Node[D] {
  override lazy val hash: D = hf.prefixedHash(MerkleTree.LeafPrefix, data)

  override def toString: String = s"Leaf(${Base58.encode(hash)})"
}

case class EmptyNode[D <: Digest]() extends Node[D] {
  override val hash: D = Array[Byte]().asInstanceOf[D]
}
