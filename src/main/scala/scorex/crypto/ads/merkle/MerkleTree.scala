package scorex.crypto.ads.merkle

import scorex.crypto.hash.CryptographicHash

trait MerkleTree[HashFn <: CryptographicHash] {
  type Digest = HashFn#Digest

  def proofByIndex(index: Position): Option[MerklePath[HashFn]]
}


trait MerklizedSeq[HashFn <: CryptographicHash] {
  val tree: MerkleTree[HashFn]

  def getDataElement(index: Long): Option[Array[Byte]]

  def byIndex(index: Position): Option[AuthDataBlock[HashFn]] = tree.proofByIndex(index) map { proof =>
    AuthDataBlock(getDataElement(index).get, proof)
  }
}


sealed trait MerklizedSeqModification {
  val position: Position
}


case class MerklizedSeqAppend(override val position: Position, element: Array[Byte]) extends MerklizedSeqModification

case class MerklizedSeqRemoval(override val position: Position) extends MerklizedSeqModification


trait VersionedMerklizedSeq[HashFn <: CryptographicHash] extends MerklizedSeq[HashFn] {
  val version: Long

  protected def setDataElement(index: Long, element: Array[Byte])

  def update(updatePlan: Iterable[MerklizedSeqModification]): VersionedMerklizedSeq[HashFn] = {
    this
  }
}