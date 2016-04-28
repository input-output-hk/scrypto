package scorex.crypto.authds.merkle

import scorex.crypto.authds.storage.{BlobStorage, StorageType, VersionedStorage}
import scorex.crypto.hash.{Blake2b256, CryptographicHash}
import scorex.utils.ScryptoLogging

import scala.annotation.tailrec
import scala.collection.mutable
import scala.util.{Failure, Try}


trait MerkleTree[HashFn <: CryptographicHash, ST <: StorageType] extends ScryptoLogging {

  import MerkleTree._

  protected type Level <: BlobStorage[ST]
  protected type LevelId = Int

  protected type LPos = (LevelId, Position)
  type Digest = HashFn#Digest

  val hashFunction: HashFn

  //todo: change with precomputed table?

  private lazy val emptyHash0 = hashFunction(Array[Byte]()).dropRight(1)

  private lazy val emptyHashesCache = mutable.Map[LevelId, Digest]()

  emptyHashesCache.put(0, emptyHash0)

  private def emptyHashTreeRoot(height: LevelId): Digest = {
    height match {
      case 0 => emptyHash0
      case _ =>
        val h = emptyHashTreeRoot(height - 1)
        hashFunction(h ++ h)
    }
  }

  protected def emptyTreeHash(level: LevelId): Digest = {
    emptyHashesCache.get(level) match {
      case Some(hash) => hash
      case None => emptyHashTreeRoot(level)
    }
  }

  protected def createLevel(level: LevelId, version: VersionedStorage[ST]#VersionTag): Try[Level]

  protected def getLevel(level: LevelId): Option[Level]

  def size: Long

  def height: Int = calculateRequiredLevel(size)

  def rootHash: Digest = getHash((height, 0)).get

  /**
    * Return AuthData at position $index
    */
  def proofByIndex(index: Position): Option[MerklePath[HashFn]] = {
    val nonEmptyBlocks = size

    if (index < nonEmptyBlocks && index >= 0) {
      @tailrec
      def calculateTreePath(n: Position, currentLevel: Int, acc: Seq[Digest] = Seq()): Seq[Digest] = {
        if (currentLevel < height) {
          val hashOpt = if (n % 2 == 0) getHash((currentLevel, n + 1)) else getHash((currentLevel, n - 1))
          hashOpt match {
            case Some(h) =>
              calculateTreePath(n / 2, currentLevel + 1, h +: acc)
            case None if currentLevel == 0 && index == nonEmptyBlocks - 1 =>
              calculateTreePath(n / 2, currentLevel + 1, emptyTreeHash(currentLevel) +: acc)
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

  def getHash(key: LPos): Option[Digest] = {
    def setTreeElement(key: LPos, value: Digest): Unit = Try {
      getLevel(key._1).get.set(key._2, value)
    }.recoverWith { case t: Throwable =>
      log.warn("Failed to set key:" + key, t)
      Failure(t)
    }

    val level = key._1

    getLevel(level).get.get(key._2) match {
      //todo: exception
      case None =>
        if (level > 0) {
          val h1 = getHash((level - 1, key._2 * 2))
          val h2 = getHash((level - 1, key._2 * 2 + 1))
          val calculatedHash = (h1, h2) match {
            case (Some(hash1), Some(hash2)) => hashFunction(hash1 ++ hash2)
            case (Some(h), None) => hashFunction(h ++ emptyTreeHash(level - 1))
            case (None, Some(h)) => hashFunction(emptyTreeHash(level - 1) ++ h)
            case (None, None) => emptyTreeHash(level)
          }
          setTreeElement(key, calculatedHash)
          Some(calculatedHash)
        } else {
          None
        }
      case digest =>
        digest
    }
  }
}

object MerkleTree {
  type Position = Long
  val DefaultHashFunction = Blake2b256

  def calculateRequiredLevel(numberOfDataBlocks: Position): Int = {
    def log2(x: Double): Double = math.log(x) / math.log(2)
    math.ceil(log2(numberOfDataBlocks)).toInt
  }
}