package scorex.crypto.ads.merkle

import scorex.crypto.hash.CryptographicHash

case class MerkleProof[HashFunction <: CryptographicHash](index: Position, merklePath: Seq[CryptographicHash#Digest])