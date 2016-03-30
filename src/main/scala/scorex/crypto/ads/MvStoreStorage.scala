package scorex.crypto.ads

import org.h2.mvstore.MVStore
import scorex.utils.ScryptoLogging

trait MvStoreStorage[Key, Value] extends KVStorage[Key, Value, MvStoreStorageType] with ScryptoLogging {

  val fileNameOpt: Option[String]

  lazy val mvs = MVStore.open(fileNameOpt.orNull)

  lazy val map = mvs.openMap[Key, Value]("data")

  override def size: Long = map.sizeAsLong()

  override def set(key: Key, value: Value): Unit = map.put(key, value)

  override def get(key: Key): Option[Value] = Option(map.get(key))

  override def close(): Unit = mvs.close()

  override def commit(): Unit = mvs.commit()
}
