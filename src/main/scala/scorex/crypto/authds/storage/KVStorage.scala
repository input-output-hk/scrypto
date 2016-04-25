package scorex.crypto.authds.storage

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

trait VersionedStorage[ST <: StorageType] {
  type VersionTag = Long

  def putVersionTag(versionTag: VersionTag)

  def lastVersion: VersionTag = Try(allVersions().max).getOrElse(0L)

  def allVersions(): Seq[VersionTag]

  def rollbackTo(versionTag: VersionTag): Try[VersionedStorage[ST]]
}

trait VersionedKVStorage[Key, Value, ST <: StorageType]
  extends KVStorage[Key, Value, ST] with VersionedStorage[ST] {

  def commitAndMark(versionOpt:Option[VersionTag]): Unit = {
    commit()
    putVersionTag(versionOpt.getOrElse(lastVersion + 1))
  }

  def commitAndMark(): Unit = commitAndMark(None)

  def batchUpdate(newElements: Iterable[(Key, Option[Value])]): VersionedKVStorage[Key, Value, ST] = {
    newElements.foreach { case (key, valueOpt) =>
      valueOpt match {
        case Some(value) => set(key, value)
        case None => unset(key)
      }
    }
    commitAndMark()
    this
  }
}

trait LazyIndexedBlobStorage[ST <: StorageType] extends KVStorage[Long, Array[Byte], ST]

trait VersionedLazyIndexedBlobStorage[ST <: StorageType]
  extends LazyIndexedBlobStorage[ST] with VersionedKVStorage[Long, Array[Byte], ST]

class MvStoreLazyIndexedBlobStorage(override val fileNameOpt: Option[String])
  extends LazyIndexedBlobStorage[MvStoreStorageType] with MvStoreKvStorage[Long, Array[Byte]]

class MvStoreVersionedLazyIndexedBlobStorage(override val fileNameOpt: Option[String])
  extends VersionedLazyIndexedBlobStorage[MvStoreStorageType] with MvStoreVersionedKvStorage[Long, Array[Byte]]