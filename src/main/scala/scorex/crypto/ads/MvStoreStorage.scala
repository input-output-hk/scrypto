package scorex.crypto.ads

import org.h2.mvstore.MVStore
import scorex.utils.ScryptoLogging

trait MvStoreStorage[Key, Value] extends KVStorage[Key, Value] with ScryptoLogging {

  val fileName: String

  lazy val mvs = MVStore.open(fileName)
  lazy val map = mvs.openMap[Key, Value]("data")

  override def set(key: Key, value: Value): Unit = map.put(key, value)

  override def get(key: Key): Option[Value] = Option(map.get(key))

  override def close(): Unit = mvs.close()

  override def commit(): Unit = mvs.commit()
}
