package scorex.crypto.authds.merkle.versioned

import java.io.RandomAccessFile

import scorex.crypto.authds.merkle.MerkleTree.Position
import scorex.crypto.authds.merkle.MerklizedSeq
import scorex.crypto.authds.storage.{MvStoreStorageType, MvStoreVersionedBlobStorage, StorageType, VersionedBlobStorage}
import scorex.crypto.hash.CryptographicHash
import scorex.utils.ScryptoLogging

import scala.annotation.tailrec
import scala.util.{Failure, Success, Try}

/*
todo: repair
 */

trait VersionedMerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType]
  extends MerklizedSeq[HashFn, ST] with ScryptoLogging {

  override protected[merkle] val tree: VersionedMerkleTree[HashFn, ST]

  override protected[merkle] val seq: VersionedBlobStorage[ST]

  private lazy val hashFn = tree.hashFunction

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
          require(removal.position > rmTail.headOption.map(_.position).getOrElse(-1L),
            "Removals should be ordered in decreasing order")

          updateStep(rmTail, appTail, size, updatesPlan :+ (removal.position -> Some(append.element)))

        case (Nil, append :: appTail) =>
          updateStep(Nil, appTail, size + 1, updatesPlan :+ (size -> Some(append.element)))

        case (removal :: rmTail, Nil) =>
          require(removal.position > rmTail.headOption.map(_.position).getOrElse(-1L),
            "Removals should be ordered in decreasing order")

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
  def allVersions(): Seq[VersionedBlobStorage[ST]#VersionTag] = {
    seq.allVersions()
  }

  def consistent: Boolean = tree.consistent && seq.lastVersion == tree.lastVersion

  def rollbackTo(version: VersionedBlobStorage[ST]#VersionTag): Try[VersionedMerklizedSeq[HashFn, ST]] = {
    seq.rollbackTo(version) match {
      case Success(_) =>
        tree.rollbackTo(version) match {
          case Success(_) =>
            Success(this)
          case Failure(e) =>
            log.error("tree rollback error", e)
            println("tree rollback error")
            e.printStackTrace()
            Failure(e)
        }
      case Failure(e) =>
        log.error("Seq rollback error", e)
        println("seq rollback error")
        e.printStackTrace()
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
      override protected[merkle] val seq: VersionedBlobStorage[MvStoreStorageType] =
        new MvStoreVersionedBlobStorage(seqFileNameOpt)

      seq.commitAndMark(Some(initialVersion))
      tree.commit(Some(initialVersion))
    }
  }

  def apply[HashFn <: CryptographicHash](treeFileNameOpt: Option[String],
                                         initialSeq: VersionedBlobStorage[MvStoreStorageType],
                                         initialVersion: Long,
                                         hashFn: HashFn): MvStoreVersionedMerklizedSeq[HashFn] = {
    new MvStoreVersionedMerklizedSeq[HashFn] {
      override protected[merkle] val seq: VersionedBlobStorage[MvStoreStorageType] = initialSeq
      override protected[merkle] val tree: VersionedMerkleTree[HashFn, MvStoreStorageType] =
        new MvStoreVersionedMerkleTree(treeFileNameOpt, hashFn) {
          override def size = initialSeq.size

          override def getHash(key: LPos): Option[Digest] = {
            key._1 == 0 match {
              case true =>
                val value = super.getHash(key).orElse(seq.get(key._2).map(hashFn.apply))
                value.foreach(e => setTreeElement(0 -> key._2, e))
                value
              case false => super.getHash(key)
            }
          }
        }

      seq.commitAndMark(Some(initialVersion))
      tree.commit(Some(initialVersion))
    }
  }


  /**
    * Create Merkle tree from file with data
    */
  //todo: pass initial version
  def fromFile[H <: CryptographicHash](fileName: String,
                                       treeFolder: Option[String],
                                       blockSize: Int,
                                       hashFn: H): VersionedMerklizedSeq[H, MvStoreStorageType] = {

    val initialVersion = 1

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

    val vms = MvStoreVersionedMerklizedSeq(
      treeFolder.map(_ + TreeFileName),
      treeFolder.map(_ + SegmentsFileName),
      initialVersion,
      hashFn)

    val appends: Seq[MerklizedSeqAppend] = (0L to nonEmptyBlocks - 1)
      .map(position => readLines(fileName, position))
      .map(MerklizedSeqAppend)
      .toList

    vms.update(List(), appends)
  }
}