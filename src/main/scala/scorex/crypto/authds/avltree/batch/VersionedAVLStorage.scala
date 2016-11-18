package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.avltree.ProverNodes

trait VersionedAVLStorage {

  type Version = Array[Byte]

  def update(topNode: ProverNodes): Unit

  def rollback(version: Version): ProverNodes

  def version: Version

  def isEmpty: Boolean

  def nonEmpty: Boolean = !isEmpty

}

object VersionedAVLStorage {
  type Version = Array[Byte]
}