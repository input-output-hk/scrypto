package scorex.crypto.authds.avltree.batch

import scala.util.Try

/**
  * Interface for persistent versioned
  */
trait VersionedAVLStorage {

  type Version = Array[Byte]

  /**
    * Synchronize storage with prover's state
    * @param batchProver - prover to synchronize storage with
    * @return
    */
  def update(batchProver: BatchAVLProver[_]): Try[Unit]

  /**
    * Return root node and tree height at version
    */
  def rollback(version: Version): Try[(ProverNodes, Int)]

  /**
    * Current version of storage. Version is prover's root hash value during last storage update.
    * @return current version, if any; None is storage is empty
    */
  def version: Option[Version]

  /**
    * If storage is empty
    * @return true is storage is empty, false otherwise
    */
  def isEmpty: Boolean = version.isEmpty

  def nonEmpty: Boolean = !isEmpty

  /**
    * Versions store keeps and can rollback to.
    * @return versions store keeps
    */
  def rollbackVersions: Iterable[Version]
}

object VersionedAVLStorage {
  type Version = Array[Byte]
}