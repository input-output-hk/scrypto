package scorex.crypto.authds.merkle.fixed

import scorex.crypto.authds.merkle.MerkleTree
import scorex.crypto.authds.storage.{MvStoreStorageType, StorageType}
import scorex.crypto.hash.CryptographicHash



trait FixedMerkleTree[HashFn <: CryptographicHash, ST <: StorageType] extends MerkleTree[HashFn, ST] {
  override val size: Long
}


abstract class MvStoreFixedMerkleTree[HashFn <: CryptographicHash](override val hashFunction: HashFn)
  extends FixedMerkleTree[HashFn, MvStoreStorageType] {
}