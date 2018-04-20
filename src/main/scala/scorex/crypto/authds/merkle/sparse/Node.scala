package scorex.crypto.authds.merkle.sparse

import scorex.crypto.authds.LeafData
import scorex.crypto.encode.Base16
import scorex.crypto.hash._

trait Node[D <: Digest] {
  def hash: D

  def isNull: Boolean
}

object Node {
  type ID = BigInt
}

case class InternalNode[D <: Digest](left: Option[Node[D]],
                                     right: Option[Node[D]])
                                    (implicit val hf: CryptographicHash[D]) extends Node[D] {

  lazy val leftHash: Array[Byte] =  left.map(_.hash).getOrElse(Array[Byte]())

  lazy val rightHash: Array[Byte] = right.map(_.hash).getOrElse(Array[Byte]())

  override lazy val isNull: Boolean = left.isEmpty && right.isEmpty

  override lazy val hash: D = if (isNull) Array[Byte]().asInstanceOf[D] else hf.hash(leftHash ++ rightHash)
}

case class Leaf[D <: Digest](idx: Node.ID, data: LeafData)(implicit val hf: CryptographicHash[D]) extends Node[D] {

  override lazy val hash: D = hf.hash(idx.toByteArray ++ data)

  override lazy val isNull: Boolean = false

  override def toString: String = s"Leaf(id: $idx , hash: ${Base16.encode(hash)})"
}

case class LeafHash[D <: Digest](override val hash: D) extends Node[D] {

  override lazy val isNull: Boolean = false

  override def toString: String = s"LeafHash(hash: ${Base16.encode(hash)})"
}