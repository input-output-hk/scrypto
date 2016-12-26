package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary._
import scorex.crypto.authds.UpdateF
import scorex.crypto.hash.ThreadUnsafeHash

import scala.util.Try

class PersistentBatchAVLProver[HF <: ThreadUnsafeHash](private var prover: BatchAVLProver[HF],
                                                       storage: VersionedAVLStorage) extends UpdateF[Array[Byte]] {
  if (storage.nonEmpty) {
    rollback(storage.version).get
  } else {
    storage.update(prover.topNode).get
  }

  def rootHash: Label = prover.rootHash

  def performOneModification(modification: Modification): Unit = prover.performOneModification(modification)

  def performOneModification(key: AVLKey, updateFunction: UpdateFunction): Unit =
    prover.performOneModification(key, updateFunction)

  def generateProof: Array[Byte] = {
    storage.update(prover.topNode).get
    prover.generateProof.toArray
  }

  def rollback(version: VersionedAVLStorage.Version): Try[Unit] = Try {
    val recoveredTop: (ProverNodes, Int) = storage.rollback(version).get
    prover = new BatchAVLProver(prover.keyLength, prover.valueLength, Some(recoveredTop))(prover.hf)
  }

  def checkTree(postProof: Boolean = false): Unit = prover.checkTree(postProof)
}