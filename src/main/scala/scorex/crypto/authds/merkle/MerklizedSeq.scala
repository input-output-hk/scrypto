package scorex.crypto.authds.merkle

import scorex.crypto.authds.merkle.MerkleTree.Position
import scorex.crypto.authds.storage.{StorageType, BlobStorage}
import scorex.crypto.hash.CryptographicHash


trait MerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType] {
  protected val tree: MerkleTree[HashFn, ST]
  protected val seq: BlobStorage[ST]

  def size: Long = seq.size

  def getDataElement(index: Long): Option[Array[Byte]] = seq.get(index)

  def byIndex(index: Position): Option[AuthData[HashFn]] = tree.proofByIndex(index) map { proof =>
    AuthData(getDataElement(index).get, proof)
  }
}