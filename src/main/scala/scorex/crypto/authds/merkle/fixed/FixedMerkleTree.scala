package scorex.crypto.authds.merkle.fixed

import scorex.crypto.authds.merkle.MerkleTree
import scorex.crypto.authds.storage.StorageType
import scorex.crypto.hash.CryptographicHash

trait FixedMerkleTree[HashFn <: CryptographicHash, ST <: StorageType] extends MerkleTree[HashFn, ST] {
  override val size: Long
}