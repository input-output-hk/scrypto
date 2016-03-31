package scorex.crypto.ads.merkle

import scorex.crypto.ads.{VersionedLazyIndexedBlobStorage, MvStoreVersionedLazyIndexedBlobStorage, LazyIndexedBlobStorage, StorageType}
import scorex.crypto.hash.CryptographicHash

import scala.annotation.tailrec


trait MerkleTree[HashFn <: CryptographicHash, ST <: StorageType] {
  type Digest = HashFn#Digest

  val hashFunction: HashFn

  protected lazy val emptyHash = hashFunction(Array[Byte]())

  def proofByIndex(index: Position): Option[MerklePath[HashFn]]
}


trait MerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType] {
  protected val tree: MerkleTree[HashFn, ST]
  protected val seq: LazyIndexedBlobStorage[ST]

  def getDataElement(index: Long): Option[Array[Byte]] = seq.get(index)

  def byIndex(index: Position): Option[AuthDataBlock[HashFn]] = tree.proofByIndex(index) map { proof =>
    AuthDataBlock(getDataElement(index).get, proof)
  }
}


sealed trait MerklizedSeqModification {
  val position: Position
}

final case class MerklizedSeqAppend(override val position: Position, element: Array[Byte]) extends MerklizedSeqModification

final case class MerklizedSeqRemoval(override val position: Position) extends MerklizedSeqModification


/*
todo: versioned support for MapDB / MvStore
todo: empty elements in Merkle trees
 */

trait VersionedMerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType] extends MerklizedSeq[HashFn, ST] {

  override protected val tree: MerkleTree[HashFn, ST] //todo: versioned Merkle tree

  override protected val seq: VersionedLazyIndexedBlobStorage[ST]

  val version: Long

  protected def setDataElement(index: Long, element: Array[Byte]) = seq.set(index, element)

  def update(removals: Seq[MerklizedSeqRemoval],
             appends: Seq[MerklizedSeqAppend]): VersionedMerklizedSeq[HashFn, ST] = {

    @tailrec
    def updateStep(removals: Seq[MerklizedSeqRemoval],
                   appends: Seq[MerklizedSeqAppend],
                   updatesPlan: Seq[(Position, Array[Byte])]): Seq[(Position, Array[Byte])] = {
      (removals, appends) match{
        case (removal :: rmTail, append :: appTail) =>
          seq.set(removal.position, append.element)
          updateStep(rmTail, appTail, updatesPlan :+ (removal.position -> append.element))

        case (Nil, append :: appTail) =>
          val position = seq.size
          seq.set(position, append.element)
          updateStep(Nil, appTail, updatesPlan :+ (position -> append.element))

        case (removal :: rmTail,  Nil) =>
          val p = seq.size - 1
          val last = seq.get(p).get
          seq.set(removal.position, last)
          seq.unset(p)
          val updates = Seq(removal.position -> last, p -> Array[Byte]()) // todo: fix empty array
          updateStep(rmTail, Nil, updatesPlan ++ updates)

        case (Nil, Nil) =>
          updatesPlan
      }
    }

    val updatesPlan = updateStep(removals, appends, Seq())
    seq.batchUpdate(updatesPlan, "")
    this
  }
}