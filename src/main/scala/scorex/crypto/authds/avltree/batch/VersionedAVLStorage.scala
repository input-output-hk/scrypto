package scorex.crypto.authds.avltree.batch

import scala.util.Try

trait VersionedAVLStorage {

  type Version = Array[Byte]

  def update(batchProver: BatchAVLProver[_]): Try[Unit]

  /**
    * Return root node and tree height at version
    */
  def rollback(version: Version): Try[(ProverNodes, Int)]

  def version: Version

  def isEmpty: Boolean

  def nonEmpty: Boolean = !isEmpty

}

object VersionedAVLStorage {
  type Version = Array[Byte]
}