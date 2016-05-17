package scorex.crypto.authds.merkle

import scorex.crypto.authds.AuthenticatedDictionary
import scorex.crypto.authds.storage.{BlobStorage, StorageType}
import scorex.crypto.hash.CryptographicHash


trait MerklizedIndexedSeq[HashFn <: CryptographicHash, ST <: StorageType]
  extends AuthenticatedDictionary[HashFn, MerklePath[HashFn], ST] {

  override type Key = Long

  protected val tree: MerkleTree[HashFn, ST]
  override protected val seq: BlobStorage[ST]

  def elementAndProof(index: Key): Option[MerkleAuthData[HashFn]] = tree.proofByIndex(index) map { proof =>
    MerkleAuthData(element(index).get, proof)
  }
}