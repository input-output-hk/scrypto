package scorex.crypto.ads

trait KVStorage[Key, Value, ST <: StorageType] {
  def size: Long

  def set(key: Key, value: Value): Unit

  def get(key: Key): Option[Value]

  def commit(): Unit

  def close(): Unit

  def containsKey(key: Key): Boolean = get(key).isDefined
}

trait LazyIndexedBlobStorage[ST <: StorageType] extends KVStorage[Long, Array[Byte], ST]


class MapDbLazyIndexedBlobStorage(override val fileNameOpt: Option[String])
  extends LazyIndexedBlobStorage[MapDbStorageType] with MapDBStorage[Long, Array[Byte]]

class MvStoreLazyIndexedBlobStorage(override val fileNameOpt: Option[String])
  extends LazyIndexedBlobStorage[MvStoreStorageType] with MvStoreStorage[Long, Array[Byte]]