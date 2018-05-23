package scorex.crypto.authds.merkle

import scorex.crypto.authds.LeafData
import scorex.crypto.hash._
import scorex.utils.ScryptoLogging

trait Node[D <: Digest] extends ScryptoLogging {
  def hash: D
}

case class InternalNode[D <: Digest](left: Node[D], right: Node[D])
                                    (implicit val hf: CryptographicHash[D]) extends Node[D] {

  override lazy val hash: D = hf.prefixedHash(MerkleTree.InternalNodePrefix, left.hash, right.hash)

  override def toString: String = s"InternalNode(" +
    s"left: ${encoder.encode(left.hash)}, " +
    s"right: ${if(right.hash.isEmpty) "null" else encoder.encode(right.hash)}," +
    s"hash: ${encoder.encode(hash)})"
}

case class Leaf[D <: Digest](data: LeafData)(implicit val hf: CryptographicHash[D]) extends Node[D] {
  override lazy val hash: D = hf.prefixedHash(MerkleTree.LeafPrefix, data)

  override def toString: String = s"Leaf(${encoder.encode(hash)})"
}

case class EmptyNode[D <: Digest]()(implicit val hf: CryptographicHash[D]) extends Node[D] {
  override val hash: D = Array[Byte]().asInstanceOf[D]
}

case class EmptyRootNode[D <: Digest]()(implicit val hf: CryptographicHash[D]) extends Node[D] {
  // .get is secure here since we know that array size equals to digest size
  override val hash: D = hf.byteArrayToDigest(Array.fill(hf.DigestSize)(0: Byte)).get

  override def toString: String = s"EmptyRootNode(${encoder.encode(hash)})"
}
