package scorex.crypto.authds.merkle

import scorex.crypto.authds.{VersionedStorage, LazyIndexedBlobStorage, StorageType}
import scorex.crypto.hash.CryptographicHash
import scorex.utils.ScryptoLogging

import scala.annotation.tailrec
import scala.util.{Failure, Try}


trait MerkleTree[HashFn <: CryptographicHash, ST <: StorageType] extends ScryptoLogging {

  import MerkleTree._

  protected type Level <: LazyIndexedBlobStorage[ST]
  protected type LevelId = Int
  type Position = Long
  protected type LPos = (LevelId, Position)
  type Digest = HashFn#Digest

  val hashFunction: HashFn

  protected def createLevel(level: LevelId, version: VersionedStorage[ST]#VersionTag): Try[Level]

  protected def getLevel(level: LevelId): Option[Level]

  def size: Long

  protected lazy val emptyHash = hashFunction(Array[Byte]()).dropRight(1)

  def height: Int = calculateRequiredLevel(size)

  def rootHash: Digest = getHash((height, 0)).get

  /**
    * Return AuthDataBlock at position $index
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

  protected def setTreeElement(key: LPos, value: Digest): Unit = Try {
    getLevel(key._1).get.set(key._2, value)
  }.recoverWith { case t: Throwable =>
    log.warn("Failed to set key:" + key, t)
    Failure(t)
  }

  def getHash(key: LPos): Option[Digest] =
    getLevel(key._1).get.get(key._2) match {
      //todo: exception
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
          setTreeElement(key, calculatedHash)
          Some(calculatedHash)
        } else {
          None
        }
      case digest =>
        digest
    }
}

object MerkleTree {
  def calculateRequiredLevel(numberOfDataBlocks: Position): Int = {
    def log2(x: Double): Double = math.log(x) / math.log(2)
    math.ceil(log2(numberOfDataBlocks)).toInt
  }
}