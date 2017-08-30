package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.ADDigest
import scorex.crypto.hash.Digest

import scala.util.Try

trait VersionedAVLStorage[T <: Digest] {

  def update(batchProver: BatchAVLProver[T, _]): Try[Unit]

  /**
    * Return root node and tree height at version
    */
  def rollback(version: ADDigest): Try[(ProverNodes[T], Int)]

  def version: ADDigest

  def isEmpty: Boolean

  def nonEmpty: Boolean = !isEmpty

}
