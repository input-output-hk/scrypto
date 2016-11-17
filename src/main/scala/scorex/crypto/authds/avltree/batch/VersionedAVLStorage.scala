package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.avltree.ProverNodes

trait VersionedAVLStorage {

  type Version = Array[Byte]

  def update(topNode: ProverNodes): Unit

  def rollback(version: Version): ProverNodes

  def version: Version


}

object VersionedAVLStorage {
  type Version = Array[Byte]

  val InitialVersion: Version = Array.fill[Byte](32)(0: Byte)
}