package scorex.crypto.authds.merkle

import scorex.crypto.authds.LeafData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Digest32, _}

trait Node {
  def hash: Digest
}

case class InternalNode(left: Node, right: Node)(implicit val hf: CryptographicHash[_ <: Digest]) extends Node {
  override lazy val hash: Digest = hf.prefixedHash(MerkleTree.InternalNodePrefix, left.hash, right.hash)

  override def toString: String = s"InternalNode(" +
    s"left: ${Base58.encode(left.hash)}, " +
    s"right: ${Base58.encode(right.hash)}," +
    s"hash: ${Base58.encode(hash)})"
}

case class Leaf(data: LeafData)(implicit val hf: CryptographicHash[_ <: Digest]) extends Node {
  override lazy val hash: Digest = hf.prefixedHash(MerkleTree.LeafPrefix, data)

  override def toString: String = s"Leaf(${Base58.encode(hash)})"
}

case object EmptyNode extends Node {
  override val hash: Digest32 = Digest32 @@ Array[Byte]()
}
