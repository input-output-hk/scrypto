package scorex.crypto.ads.merkle

import scorex.crypto.hash.CryptographicHash

case class MerklePath[HashFunction <: CryptographicHash](index: Position, hashes: Seq[CryptographicHash#Digest])