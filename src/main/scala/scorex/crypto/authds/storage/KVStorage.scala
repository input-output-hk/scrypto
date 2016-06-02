package scorex.crypto.authds.storage


trait KVStorage[Key, Value, ST <: StorageType] {
  def size: Long

  def unset(key: Key): Unit

  def set(key: Key, value: Value): Unit

  def get(key: Key): Option[Value]

  def commit(): Unit

  def close(): Unit

  def containsKey(key: Key): Boolean = get(key).isDefined
}

trait BlobStorage[ST <: StorageType] extends KVStorage[Long, Array[Byte], ST]

class MvStoreBlobStorage(override val fileNameOpt: Option[String])
  extends BlobStorage[MvStoreStorageType] with MvStoreKvStorage[Long, Array[Byte]]

class MvStoreBlobBlobStorage(override val fileNameOpt: Option[String]) extends MvStoreKvStorage[Array[Byte], Array[Byte]]