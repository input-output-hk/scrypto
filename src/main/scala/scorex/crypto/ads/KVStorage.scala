package scorex.crypto.ads

trait KVStorage[Key, Value] {

  def set(key: Key, value: Value): Unit

  def get(key: Key): Option[Value]

  def commit(): Unit

  def close(): Unit

  def containsKey(key: Key): Boolean = get(key).isDefined
}

trait LazyIndexedBlobStorage extends KVStorage[Long, Array[Byte]]

class MapDbLazyIndexedBlobStorage(override val fileName: String)
  extends LazyIndexedBlobStorage with MapDBStorage[Long, Array[Byte]]