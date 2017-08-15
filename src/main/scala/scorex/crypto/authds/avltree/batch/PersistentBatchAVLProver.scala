package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.avltree.{AVLKey, AVLValue}
import scorex.crypto.hash.ThreadUnsafeHash

import scala.util.Try

class PersistentBatchAVLProver[HF <: ThreadUnsafeHash](private var avlProver: BatchAVLProver[HF],
                                                       storage: VersionedAVLStorage) {
  if (storage.nonEmpty) {
    rollback(storage.version).get
  } else {
    storage.update(avlProver).get
  }

  def digest: Array[Byte] = avlProver.digest

  def height: Int = avlProver.rootNodeHeight

  def prover(): BatchAVLProver[HF] = avlProver

  def unauthenticatedLookup(key: AVLKey): Option[AVLValue] = avlProver.unauthenticatedLookup(key)

  def performOneOperation(operation: Operation): Try[Option[AVLValue]] = avlProver.performOneOperation(operation)

  //side effect: avlProver modifies itself
  def generateProof(): Array[Byte] = {
    storage.update(avlProver).get
    avlProver.generateProof()
  }

  def rollback(version: VersionedAVLStorage.Version): Try[Unit] = Try {
    val recoveredTop: (ProverNodes, Int) = storage.rollback(version).get
    avlProver = new BatchAVLProver(avlProver.keyLength, avlProver.valueLengthOpt, Some(recoveredTop))(avlProver.hf)
  }

  def checkTree(postProof: Boolean = false): Unit = avlProver.checkTree(postProof)
}