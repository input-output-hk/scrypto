package scorex.crypto.authds.skiplist

import scorex.crypto.authds.DataProof
import scorex.crypto.authds.merkle.MerkleTree.Position
import scorex.crypto.encode._
import scorex.crypto.hash.CryptographicHash


case class SLPath(hashes: Seq[CryptographicHash#Digest]) extends DataProof {
  override def toString: String = s"(hashes: ${hashes.map(Base16.encode)})"
}