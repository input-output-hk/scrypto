package scorex.crypto.ads.merkle

import java.io.RandomAccessFile

import scorex.crypto.ads._
import scorex.crypto.hash.CryptographicHash
import scorex.utils.ScryptoLogging

class MerkleTreeImpl[HashFn <: CryptographicHash, ST <: StorageType](override val storage: TreeStorage[HashFn, ST],
                                                                     override val nonEmptyBlocks: Position,
                                                                     override val hashFunction: HashFn)
  extends MerkleTree[HashFn, ST] with ScryptoLogging

object MerkleTreeImpl {

  import MerkleTree._

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
      case _: MapDbStorageType =>
        (new MapDbTreeStorage[H](Some(treeFolder + TreeFileName), level),
          new MapDbLazyIndexedBlobStorage(Some(treeFolder + SegmentsFileName)))
      case _: MvStoreStorageType =>
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
}