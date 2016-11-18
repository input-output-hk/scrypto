package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary._
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree.{ProverNodes, _}
import scorex.crypto.hash.ThreadUnsafeHash

import scala.util.Try

class PersistentBatchAVLProver[HF <: ThreadUnsafeHash](private var prover: BatchAVLProver[HF],
                                                       storage: VersionedAVLStorage) extends UpdateF[Array[Byte]] {
  if (storage.nonEmpty) {
    rollback(storage.version)
  } else {
    storage.update(prover.topNode)
  }

  def rootHash: Label = prover.rootHash

  def performOneModification(modification: Modification): Unit = prover.performOneModification(modification)

  def performOneModification(key: AVLKey, updateFunction: UpdateFunction): Unit =
    prover.performOneModification(key, updateFunction)

  def generateProof: Array[Byte] = {
    storage.update(prover.topNode)
    prover.generateProof.toArray
  }

  def rollback(version: VersionedAVLStorage.Version): Try[Unit] = Try {
    val recoveredTop: ProverNodes = storage.rollback(version)
    prover = new BatchAVLProver(Some(recoveredTop), prover.keyLength, prover.valueLength)(prover.hf)
  }
}