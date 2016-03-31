package scorex.crypto.ads.merkle

import scorex.crypto.ads.StorageType
import scorex.crypto.hash.CryptographicHash

trait MerkleTree[HashFn <: CryptographicHash, ST <: StorageType] {
  type Digest = HashFn#Digest

  val hashFunction: HashFn

  protected lazy val emptyHash = hashFunction(Array[Byte]())

  def proofByIndex(index: Position): Option[MerklePath[HashFn]]
}