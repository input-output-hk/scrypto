package scorex.crypto.ads.merkle

import scorex.crypto.hash.CryptographicHash

trait MerkleTree[HashFn <: CryptographicHash] {
  type Digest = HashFn#Digest

  def proofByIndex(index: Position): Option[MerklePath[HashFn]]
}
