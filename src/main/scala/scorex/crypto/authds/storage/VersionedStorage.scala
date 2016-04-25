package scorex.crypto.authds.storage

import scala.util.Try


trait VersionedStorage[ST <: StorageType] {
  type VersionTag = Long

  def putVersionTag(versionTag: VersionTag)

  def lastVersion: VersionTag = Try(allVersions().max).getOrElse(0L)

  def allVersions(): Seq[VersionTag]

  def rollbackTo(versionTag: VersionTag): Try[VersionedStorage[ST]]
}
