package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.ADDigest
import scorex.crypto.hash.Digest

import scala.util.Try

/**
  * Interface for persistent versioned
  */
trait VersionedAVLStorage[D <: Digest] {

  /**
    * Synchronize storage with prover's state
    *
    * @param batchProver - prover to synchronize storage with
    * @return
    */
  def update[K <: Array[Byte], V <: Array[Byte]](batchProver: BatchAVLProver[D, _],
                                                 additionalData: Seq[(K, V)]): Try[Unit]

  def update(batchProver: BatchAVLProver[D, _]): Try[Unit] = update(batchProver, Seq())

  /**
    * Return root node and tree height at version
    */
  def rollback(version: ADDigest): Try[(ProverNodes[D], Int)]

  /**
    * Current version of storage. Version is prover's root hash value during last storage update.
    *
    * @return current version, if any; None is storage is empty
    */
  def version: Option[ADDigest]

  /**
    * If storage is empty
    *
    * @return true is storage is empty, false otherwise
    */
  def isEmpty: Boolean = version.isEmpty

  def nonEmpty: Boolean = !isEmpty

  /**
    * Versions store keeps and can rollback to.
    *
    * @return versions store keeps
    */
  def rollbackVersions: Iterable[ADDigest]
}
