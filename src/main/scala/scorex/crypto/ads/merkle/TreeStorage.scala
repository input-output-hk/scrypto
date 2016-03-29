package scorex.crypto.ads.merkle

import scorex.crypto.ads._
import scorex.crypto.hash.CryptographicHash
import scorex.utils.ScryptoLogging

import scala.util.{Failure, Try}

trait TreeStorage[HashFunction <: CryptographicHash, ST <: StorageType]
  extends KVStorage[(TreeStorage.Level, TreeStorage.Position), HashFunction#Digest, ST]
  with ScryptoLogging {

  import TreeStorage._

  type Digest = HashFunction#Digest

  val fileNameOpt: Option[String]
  val levels: Int

  protected val maps: Map[Int, LazyIndexedBlobStorage[ST]]

  override def set(key: Key, value: Digest): Unit = Try {
    maps(key._1).set(key._2, value)
  }.recoverWith { case t: Throwable =>
    log.warn("Failed to set key:" + key, t)
    Failure(t)
  }

  override def get(key: Key): Option[Digest] = maps(key._1).get(key._2)
}


class MapDbTreeStorage[HashFunction <: CryptographicHash]
(override val fileNameOpt: Option[String], override val levels: Int)
  extends TreeStorage[HashFunction, MapDbStorageType] {

  override protected val maps = ((0 to levels) map { n: Int =>
    n -> new MapDbLazyIndexedBlobStorage(fileNameOpt.map(_ + n + ".mapDB"))
  }).toMap

  override def close(): Unit = {
    commit()
    maps.foreach(_._2.close())
  }

  override def commit(): Unit = maps.foreach(_._2.commit())
}

class MvStoreTreeStorage[HashFunction <: CryptographicHash]
(override val fileNameOpt: Option[String], override val levels: Int)
  extends TreeStorage[HashFunction, MvStoreStorageType] {

  override protected val maps = ((0 to levels) map { n: Int =>
    n -> new MvStoreLazyIndexedBlobStorage(fileNameOpt.map(_ + n + ".mapDB"))
  }).toMap

  override def close(): Unit = {
    commit()
    maps.foreach(_._2.close())
  }

  override def commit(): Unit = maps.foreach(_._2.commit())
}

object TreeStorage {
  type Level = Int
  type Position = Long
  type Key = (Level, Position)
}