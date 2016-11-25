package scrypto.authds.avltree.batch

import scrypto.authds.TwoPartyDictionary._
import scrypto.authds.UpdateF
import scrypto.authds.avltree.{ProverNodes, _}
import scrypto.hash.ThreadUnsafeHash

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
    val recoveredTop: ProverNodes = storage.rollback(version).get
    prover = new BatchAVLProver(Some(recoveredTop), prover.keyLength, prover.valueLength)(prover.hf)
  }
}