package scorex.crypto.authds.merkle.fixed

import scorex.crypto.authds.merkle.MerkleTree
import scorex.crypto.authds.storage.{MvStoreStorageType, StorageType, VersionedStorage}
import scorex.crypto.hash.CryptographicHash

import scala.util.Try


trait FixedMerkleTree[HashFn <: CryptographicHash, ST <: StorageType] extends MerkleTree[HashFn, ST] {
  override val size: Long
}
