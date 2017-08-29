package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.ADDigest

import scala.util.Try

trait VersionedAVLStorage {

  def update(batchProver: BatchAVLProver[_]): Try[Unit]

  /**
    * Return root node and tree height at version
    */
  def rollback(version: ADDigest): Try[(ProverNodes, Int)]

  def version: ADDigest

  def isEmpty: Boolean

  def nonEmpty: Boolean = !isEmpty

}
