package scorex.crypto.ads

import scala.util.Try

trait KVStorage[Key, Value, ST <: StorageType] {
  def size: Long

  def unset(key: Key): Unit

  def set(key: Key, value: Value): Unit

  def get(key: Key): Option[Value]

  def commit(): Unit

  def close(): Unit

  def containsKey(key: Key): Boolean = get(key).isDefined
}

trait VersionedKVStorage[Key, Value, ST <: StorageType] extends KVStorage[Key, Value, ST] {
  type VersionTag = String
  type InternalVersionTag

  protected def currentVersion: InternalVersionTag

  protected def putVersionTag(versionTag: VersionTag, internalVersionTag: InternalVersionTag)

  def rollbackTo(versionTag: VersionTag): Try[VersionedKVStorage[Key, Value, ST]]

  def batchUpdate(newElements: Iterable[(Key, Value)], versionTag: VersionTag): VersionedKVStorage[Key, Value, ST] = {
    newElements.foreach { case (key, value) =>
      set(key, value)
    }
    commit()
    putVersionTag(versionTag, currentVersion)
    this
  }
}

trait LazyIndexedBlobStorage[ST <: StorageType] extends KVStorage[Long, Array[Byte], ST]

trait VersionedLazyIndexedBlobStorage[ST <: StorageType]
  extends LazyIndexedBlobStorage[ST] with VersionedKVStorage[Long, Array[Byte], ST]

class MapDbLazyIndexedBlobStorage(override val fileNameOpt: Option[String])
  extends LazyIndexedBlobStorage[MapDbStorageType] with MapDBStorage[Long, Array[Byte]]

class MvStoreLazyIndexedBlobStorage(override val fileNameOpt: Option[String])
  extends LazyIndexedBlobStorage[MvStoreStorageType] with MvStoreStorage[Long, Array[Byte]]

class MvStoreVersionedLazyIndexedBlobStorage(override val fileNameOpt: Option[String])
  extends VersionedLazyIndexedBlobStorage[MvStoreStorageType] with MvStoreVersionStorage[Long, Array[Byte]]