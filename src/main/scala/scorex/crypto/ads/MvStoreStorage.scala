package scorex.crypto.ads

import org.h2.mvstore.MVStore

import scala.util.{Failure, Success, Try}

trait MvStoreStorage[Key, Value] extends KVStorage[Key, Value, MvStoreStorageType] {

  val fileNameOpt: Option[String]

  protected lazy val mvs = MVStore.open(fileNameOpt.orNull)

  protected lazy val map = mvs.openMap[Key, Value]("data")

  override def size: Long = map.sizeAsLong()

  override def unset(key: Key): Unit = map.remove(key)

  override def set(key: Key, value: Value): Unit = map.put(key, value)

  override def get(key: Key): Option[Value] = Option(map.get(key))

  override def close(): Unit = mvs.close()

  override def commit(): Unit = mvs.commit()
}

trait MvStoreVersionStorage[Key, Value]
  extends VersionedKVStorage[Key, Value, MvStoreStorageType] with MvStoreStorage[Key, Value] {

  import scala.collection.JavaConversions._

  type InternalVersionTag = Long

  private val versionsMap = mvs.openMap[VersionTag, InternalVersionTag]("versions")

  override protected def putVersionTag(versionTag: VersionTag,
                                       internalVersionTag: InternalVersionTag): Unit = {
    versionsMap.put(versionTag, internalVersionTag)
    mvs.commit()
  }

  override protected def currentVersion: InternalVersionTag = mvs.getCurrentVersion

  override def allVersions():Set[VersionTag] = versionsMap.keySet().toSet

  override def rollbackTo(versionTag: VersionTag): Try[VersionedKVStorage[Key, Value, MvStoreStorageType]] = {
    Option(versionsMap.get(versionTag)) match {
      case Some(ivt) =>
        mvs.rollbackTo(ivt + 1)
        Success(this)
      case None => Failure(new Exception(s"No version $versionTag found"))
    }
  }
}