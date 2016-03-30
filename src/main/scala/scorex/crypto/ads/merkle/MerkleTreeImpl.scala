package scorex.crypto.ads.merkle

import java.io.RandomAccessFile

import scorex.crypto.ads._
import scorex.crypto.hash.CryptographicHash
import scorex.utils.ScryptoLogging

import scala.annotation.tailrec


class MerkleTreeImpl[HashFn <: CryptographicHash, ST <: StorageType](val storage: TreeStorage[HashFn, ST],
                                                                     val nonEmptyBlocks: Position,
                                                                     override val hashFunction: HashFn)
  extends MerkleTree[HashFn, ST] with ScryptoLogging {

  import MerkleTreeImpl._

  storage.commit()

  lazy val level = calculateRequiredLevel(nonEmptyBlocks)
  lazy val rootHash: Digest = getHash((level, 0)).get

  /**
    * Return AuthDataBlock at position $index
    */
  override def proofByIndex(index: Position): Option[MerklePath[HashFn]] = {
    if (index < nonEmptyBlocks && index >= 0) {
      @tailrec
      def calculateTreePath(n: Position, currentLevel: Int, acc: Seq[Digest] = Seq()): Seq[Digest] = {
        if (currentLevel < level) {
          val hashOpt = if (n % 2 == 0) getHash((currentLevel, n + 1)) else getHash((currentLevel, n - 1))
          hashOpt match {
            case Some(h) =>
              calculateTreePath(n / 2, currentLevel + 1, h +: acc)
            case None if currentLevel == 0 && index == nonEmptyBlocks - 1 =>
              calculateTreePath(n / 2, currentLevel + 1, emptyHash +: acc)
            case None =>
              log.error(s"Unable to get hash for lev=$currentLevel, position=$n")
              acc.reverse
          }
        } else {
          acc.reverse
        }
      }
      Some(MerklePath(index, calculateTreePath(index, 0)))
    } else {
      None
    }
  }

  private def getHash(key: TreeStorage.Key): Option[Digest] = {
    storage.get(key) match {
      case None =>
        if (key._1 > 0) {
          val h1 = getHash((key._1 - 1, key._2 * 2))
          val h2 = getHash((key._1 - 1, key._2 * 2 + 1))
          val calculatedHash = (h1, h2) match {
            case (Some(hash1), Some(hash2)) => hashFunction(hash1 ++ hash2)
            case (Some(h), _) => hashFunction(h ++ emptyHash)
            case (_, Some(h)) => hashFunction(emptyHash ++ h)
            case _ => emptyHash
          }
          storage.set(key, calculatedHash)
          Some(calculatedHash)
        } else {
          None
        }
      case digest =>
        digest
    }
  }
}


object MerkleTreeImpl {
  type Block = Array[Byte]

  val TreeFileName = "/hashTree"
  val SegmentsFileName = "/segments"

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

    val level = calculateRequiredLevel(nonEmptyBlocks)

    val (storage, segmentsStorage) = storageType match {
      case _:MapDbStorageType =>
        (new MapDbTreeStorage[H](Some(treeFolder + TreeFileName), level),
          new MapDbLazyIndexedBlobStorage(Some(treeFolder + SegmentsFileName)))
      case _:MvStoreStorageType =>
        (new MvStoreTreeStorage[H](Some(treeFolder + TreeFileName), level),
          new MvStoreLazyIndexedBlobStorage(Some(treeFolder + SegmentsFileName)))
    }

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

    (new MerkleTreeImpl(storage, nonEmptyBlocks, hashFn), segmentsStorage)
  }

  def calculateRequiredLevel(numberOfDataBlocks: Position): Int = {
    def log2(x: Double): Double = math.log(x) / math.log(2)
    math.ceil(log2(numberOfDataBlocks)).toInt
  }
}