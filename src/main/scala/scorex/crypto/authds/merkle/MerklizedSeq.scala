package scorex.crypto.authds.merkle

import scorex.crypto.authds._
import scorex.crypto.authds.storage.{StorageType, BlobStorage}
import scorex.crypto.hash.CryptographicHash


trait MerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType] {
  protected val tree: MerkleTree[HashFn, ST]
  protected val seq: BlobStorage[ST]

  def size: Long = seq.size

  def getDataElement(index: Long): Option[Array[Byte]] = seq.get(index)

  def byIndex(index: Position): Option[AuthDataBlock[HashFn]] = tree.proofByIndex(index) map { proof =>
    AuthDataBlock(getDataElement(index).get, proof)
  }
}