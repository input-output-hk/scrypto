package scorex.crypto.authds.merkle

import scorex.crypto.authds.LeafData
import scorex.crypto.hash._
import scorex.utils.ScorexEncoding

trait Node[D <: Digest] extends ScorexEncoding {
  def hash: D
}

/**
  * Internal node in Merkle tree
  *
  * @param left  - left child. always non-empty
  * @param right - right child. can be emptyNode
  * @param hf    - hash function
  * @tparam D - hash function application type
  */
case class InternalNode[D <: Digest](left: Node[D], right: Node[D])
                                    (implicit val hf: CryptographicHash[D]) extends Node[D] {

  override lazy val hash: D = hf.prefixedHash(MerkleTree.InternalNodePrefix, left.hash, right.hash)

  override def toString: String = s"InternalNode(" +
    s"left: ${encoder.encode(left.hash)}, " +
    s"right: ${if (right.hash.isEmpty) "null" else encoder.encode(right.hash)}," +
    s"hash: ${encoder.encode(hash)})"
}

/**
  * Merkle tree leaf
  *
  * @param data - leaf data.
  * @param hf   - hash function
  * @tparam D - hash function application type
  */
case class Leaf[D <: Digest](data: LeafData)(implicit val hf: CryptographicHash[D]) extends Node[D] {
  override lazy val hash: D = hf.prefixedHash(MerkleTree.LeafPrefix, data)

  override def toString: String = s"Leaf(${encoder.encode(hash)})"
}

/**
  * Empty Merkle tree node.
  * Either Leaf (if number of non-empty leafs is not a power of 2, remaining leafs are EmptyNode)
  * or InternalNode (if both childs of an InternalNode are empty, it is EmptyNode)
  *
  * @param hf - hash function
  * @tparam D - hash function application type
  */
case class EmptyNode[D <: Digest]()(implicit val hf: CryptographicHash[D]) extends Node[D] {
  override val hash: D = Array[Byte]().asInstanceOf[D]
}

/**
  * Empty root node. If the tree contains no elements, it's root hash is array of 0 bits of a hash function digest
  * length
  *
  * @param hf - hash function
  * @tparam D - hash function application type
  */
case class EmptyRootNode[D <: Digest]()(implicit val hf: CryptographicHash[D]) extends Node[D] {
  // .get is secure here since we know that array size equals to digest size
  override val hash: D = hf.byteArrayToDigest(Array.fill(hf.DigestSize)(0: Byte)).get

  override def toString: String = s"EmptyRootNode(${encoder.encode(hash)})"
}
