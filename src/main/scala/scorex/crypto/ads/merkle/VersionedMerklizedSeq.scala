package scorex.crypto.ads.merkle

import java.io.RandomAccessFile

import scorex.crypto.ads._
import scorex.crypto.hash.CryptographicHash
import scorex.utils.ScryptoLogging

import scala.annotation.tailrec
import scala.util.{Failure, Success, Try}

/*
todo: versioned support for MvStore
todo: empty elements in Merkle trees
 */

trait VersionedMerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType]
  extends MerklizedSeq[HashFn, ST] with ScryptoLogging {

  override protected[merkle] val tree: VersionedMerkleTree[HashFn, ST]

  override protected[merkle] val seq: VersionedLazyIndexedBlobStorage[ST]

  private lazy val hashFn = tree.hashFunction

  val version: Long = 0

  protected def setDataElement(index: Long, element: Array[Byte]) = seq.set(index, element)

  def update(removals: Seq[MerklizedSeqRemoval],
             appends: Seq[MerklizedSeqAppend]): VersionedMerklizedSeq[HashFn, ST] = {

    //todo: recheck
    @tailrec
    def updateStep(removals: Seq[MerklizedSeqRemoval],
                   appends: Seq[MerklizedSeqAppend],
                   size: Long,
                   updatesPlan: Seq[(Position, Option[Array[Byte]])]): Seq[(Position, Option[Array[Byte]])] = {
      (removals, appends) match {
        case (removal :: rmTail, append :: appTail) =>
          updateStep(rmTail, appTail, size, updatesPlan :+ (removal.position -> Some(append.element)))

        case (Nil, append :: appTail) =>
          updateStep(Nil, appTail, size + 1, updatesPlan :+ (size -> Some(append.element)))

        case (removal :: rmTail, Nil) =>
          val p = size - 1
          val last = seq.get(p).get
          val updates = Seq(removal.position -> Some(last), p -> None)
          updateStep(rmTail, Nil, size - 1, updatesPlan ++ updates)

        case (Nil, Nil) =>
          updatesPlan
      }
    }

    val updatesPlan = updateStep(removals, appends, seq.size, Seq())
    seq.batchUpdate(updatesPlan)
    tree.batchUpdate(updatesPlan.map(u => u._1 -> u._2.map(hashFn.apply)))
    this
  }

  //todo: versions for tree
  def allVersions() = {
    seq.allVersions()
  }

  def rollbackTo(version: VersionedLazyIndexedBlobStorage[ST]#VersionTag): Try[VersionedMerklizedSeq[HashFn, ST]] = {
    seq.rollbackTo(version) match {
      case Success(_) =>
        tree.rollbackTo(version) match {
          case Success(_) =>
            Success(this)
          case Failure(e) =>
            log.error("tree rollback error", e)
            println("tree rollback error")
            Failure(e)
        }
      case Failure(e) =>
        log.error("Seq rollback error", e)
        println("seq rollback error")
        Failure(e)
    }
  }

  def rootHash: HashFn#Digest = tree.rootHash
}


trait MvStoreVersionedMerklizedSeq[HashFn <: CryptographicHash]
  extends VersionedMerklizedSeq[HashFn, MvStoreStorageType]

object MvStoreVersionedMerklizedSeq {

  type Block = Array[Byte]

  val TreeFileName = "/hashTree"
  val SegmentsFileName = "/segments"

  def apply[HashFn <: CryptographicHash](treeFileNameOpt: Option[String],
                                         seqFileNameOpt: Option[String],
                                         initialVersion: Long,
                                         hashFn: HashFn): MvStoreVersionedMerklizedSeq[HashFn] = {
    new MvStoreVersionedMerklizedSeq[HashFn] {
      override protected[merkle] val tree: VersionedMerkleTree[HashFn, MvStoreStorageType] =
        new MvStoreVersionedMerkleTree(treeFileNameOpt, hashFn) {
          override def size = levels(0).size
        }
      override protected[merkle] val seq: VersionedLazyIndexedBlobStorage[MvStoreStorageType] =
        new MvStoreVersionedLazyIndexedBlobStorage(seqFileNameOpt)
      override val version: Long = initialVersion
    }
  }

  def apply[HashFn <: CryptographicHash](treeFileNameOpt: Option[String],
                                         initialSeq: VersionedLazyIndexedBlobStorage[MvStoreStorageType],
                                         initialVersion: Long,
                                         hashFn: HashFn): MvStoreVersionedMerklizedSeq[HashFn] = {
    new MvStoreVersionedMerklizedSeq[HashFn] {
      override protected[merkle] val seq: VersionedLazyIndexedBlobStorage[MvStoreStorageType] = initialSeq
      override protected[merkle] val tree: VersionedMerkleTree[HashFn, MvStoreStorageType] =
        new MvStoreVersionedMerkleTree(treeFileNameOpt, hashFn) {
          override def size = initialSeq.size
        }
      override val version: Long = initialVersion
    }
  }


  /**
    * Create Merkle tree from file with data
    */
  def fromFile[H <: CryptographicHash, ST <: StorageType](fileName: String,
                                                          treeFolder: String,
                                                          blockSize: Int,
                                                          hashFn: H)(implicit storageType: ST) = {
    val byteBuffer = new Array[Byte](blockSize)

    def readLines(bigDataFilePath: String, chunkIndex: Position): Array[Byte] = {
      val randomAccessFile = new RandomAccessFile(fileName, "r")
      try {
        val seek = chunkIndex * blockSize
        randomAccessFile.seek(seek)
        randomAccessFile.read(byteBuffer)
        byteBuffer
      } finally {
        randomAccessFile.close()
      }
    }

    val nonEmptyBlocks: Position = {
      val randomAccessFile = new RandomAccessFile(fileName, "r")
      try {
        (randomAccessFile.length / blockSize).toInt
      } finally {
        randomAccessFile.close()
      }
    }

    // val level = calculateRequiredLevel(nonEmptyBlocks)

    val vms = MvStoreVersionedMerklizedSeq(Some(treeFolder + TreeFileName), Some(treeFolder + SegmentsFileName), 0, hashFn)
    //todo: finish vms

    //vms.update(Nil,)


    /*
    def processBlocks(position: Position = 0): Unit = {
      val block: Block = readLines(fileName, position)
      segmentsStorage.set(position, block)
      storage.set((0, position), hashFn(block))
      if (position < nonEmptyBlocks - 1) {
        processBlocks(position + 1)
      }
    }

    processBlocks()

    segmentsStorage.commit()
    storage.commit()

    */
    vms
  }
}
