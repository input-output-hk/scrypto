package scorex.crypto.authds.skiplist

import scorex.crypto.authds.DataProof
import scorex.crypto.authds.merkle.MerkleTree.Position
import scorex.crypto.encode._
import scorex.crypto.hash.CryptographicHash


case class SLPath(levHashes: Seq[LevHash]) extends DataProof {

  lazy val hashes: Seq[CryptographicHash#Digest] = levHashes.map(_.h)
  lazy val levels: Seq[Int] = levHashes.map(_.l)

  override def toString: String = levHashes.mkString(", ")
}

case class LevHash(h: CryptographicHash#Digest, l: Int) {
  override def toString: String = s"${Base58.encode(h).take(12)}|$l"
}