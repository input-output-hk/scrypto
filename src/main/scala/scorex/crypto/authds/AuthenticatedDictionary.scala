package scorex.crypto.authds

import scorex.crypto.authds.merkle.MerkleAuthData
import scorex.crypto.authds.storage.{KVStorage, StorageType}
import scorex.crypto.hash.CryptographicHash

/**
  * Created by kushti on 17.05.16.
  */
trait AuthenticatedDictionary[HashFn <: CryptographicHash, ST <: StorageType] {
  type Key
  type Value = Array[Byte]

  protected val seq: KVStorage[Key, Value, ST]

  def size: Long = seq.size

  def element(index: Key): Option[Array[Byte]] = seq.get(index)

  def elementAndProof(index: Key): Option[MerkleAuthData[HashFn]]
}
