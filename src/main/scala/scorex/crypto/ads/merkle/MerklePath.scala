package scorex.crypto.ads.merkle

import scorex.crypto.encode._
import scorex.crypto.hash.CryptographicHash

case class MerklePath[HashFunction <: CryptographicHash](index: Position, hashes: Seq[CryptographicHash#Digest]) {
  override def toString:String = s"(Index: $index, hashes: ${hashes.map(Base16.encode)})"
}