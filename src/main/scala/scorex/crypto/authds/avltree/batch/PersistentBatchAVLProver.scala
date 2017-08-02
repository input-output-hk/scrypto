package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.avltree.{AVLKey, AVLValue}
import scorex.crypto.hash.ThreadUnsafeHash

import scala.util.Try

class PersistentBatchAVLProver[HF <: ThreadUnsafeHash](private var prover: BatchAVLProver[HF],
                                                       storage: VersionedAVLStorage) {
  if (storage.nonEmpty) {
    rollback(storage.version).get
  } else {
    storage.update(prover).get
  }

  def digest: Array[Byte] = prover.digest

  def height: Int = prover.rootNodeHeight

  def unauthenticatedLookup(key: AVLKey): Option[AVLValue] = prover.unauthenticatedLookup(key)

  def performOneOperation(operation: Operation): Unit = prover.performOneOperation(operation)

  def generateProof: Array[Byte] = {
    storage.update(prover).get
    prover.generateProof()
  }

  def rollback(version: VersionedAVLStorage.Version): Try[Unit] = Try {
    val recoveredTop: (ProverNodes, Int) = storage.rollback(version).get
    prover = new BatchAVLProver(prover.keyLength, prover.valueLengthOpt, Some(recoveredTop))(prover.hf)
  }

  def checkTree(postProof: Boolean = false): Unit = prover.checkTree(postProof)
}