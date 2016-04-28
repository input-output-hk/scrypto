package scorex.crypto.authds.storage


trait VersionedKVStorage[Key, Value, ST <: StorageType]
  extends KVStorage[Key, Value, ST] with VersionedStorage[ST] {

  def commitAndMark(versionOpt: Option[VersionTag]): Unit = {
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


trait VersionedBlobStorage[ST <: StorageType]
  extends BlobStorage[ST] with VersionedKVStorage[Long, Array[Byte], ST]

class MvStoreVersionedBlobStorage(override val fileNameOpt: Option[String])
  extends VersionedBlobStorage[MvStoreStorageType] with MvStoreVersionedKvStorage[Long, Array[Byte]]

