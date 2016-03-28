package scorex.crypto.ads.merkle

import scorex.crypto.ads.{MapDbLazyIndexedBlobStorage, KVStorage, LazyIndexedBlobStorage}
import scorex.crypto.hash.CryptographicHash
import scorex.utils.ScryptoLogging
import scala.util.{Failure, Try}

trait TreeStorage[HashFunction <: CryptographicHash]
  extends KVStorage[(TreeStorage.Level, TreeStorage.Position), HashFunction#Digest]
  with ScryptoLogging {

  import TreeStorage._

  type Digest = HashFunction#Digest

  val fileName: String
  val levels: Int

  protected val maps: Map[Int, LazyIndexedBlobStorage]

  override def set(key: Key, value: Digest): Unit = Try {
    maps(key._1).set(key._2, value)
  }.recoverWith { case t: Throwable =>
    log.warn("Failed to set key:" + key, t)
    Failure(t)
  }

  override def get(key: Key): Option[Digest] = maps(key._1).get(key._2)
}


class MapDbTreeStorage[HashFunction <: CryptographicHash](
                                                           override val fileName: String,
                                                           override val levels: Int) extends TreeStorage[HashFunction] {

  override protected val maps: Map[Int, LazyIndexedBlobStorage] = ((0 to levels) map { n: Int =>
    n -> new MapDbLazyIndexedBlobStorage(fileName + n + ".mapDB")
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