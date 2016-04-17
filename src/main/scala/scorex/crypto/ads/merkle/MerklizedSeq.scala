package scorex.crypto.ads.merkle

import scorex.crypto.ads._
import scorex.crypto.hash.CryptographicHash


trait MerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType] {
  protected val tree: MerkleTree[HashFn, ST]
  protected val seq: LazyIndexedBlobStorage[ST]

  def size: Long = seq.size

  def getDataElement(index: Long): Option[Array[Byte]] = seq.get(index)

  def byIndex(index: Position): Option[AuthDataBlock[HashFn]] = tree.proofByIndex(index) map { proof =>
    AuthDataBlock(getDataElement(index).get, proof)
  }
}