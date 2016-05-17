package scorex.crypto.authds

import scorex.crypto.authds.storage.{KVStorage, StorageType}

trait AuthenticatedDictionary[Proof <: DataProof, ST <: StorageType] {
  type Key
  type Value = Array[Byte]

  protected val seq: KVStorage[Key, Value, ST]

  def size: Long = seq.size

  def element(index: Key): Option[Array[Byte]] = seq.get(index)

  def elementAndProof(index: Key): Option[AuthData[Proof]]
}