package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds._
import scorex.crypto.hash._

import scala.util.Try

abstract class PersistentBatchAVLProver[D <: Digest, HF <: ThreadUnsafeHash[D]] {

  var avlProver: BatchAVLProver[D, HF]
  val storage: VersionedAVLStorage[D]

  def digest: ADDigest = avlProver.digest

  def height: Int = avlProver.rootNodeHeight

  def prover(): BatchAVLProver[D, HF] = avlProver

  def unauthenticatedLookup(key: ADKey): Option[ADValue] = avlProver.unauthenticatedLookup(key)

  def performOneOperation(operation: Operation): Try[Option[ADValue]] = avlProver.performOneOperation(operation)

  //side effect: avlProver modifies itself
  def generateProof(): SerializedAdProof = {
    storage.update(avlProver).get
    avlProver.generateProof()
  }

  def rollback(version: ADDigest): Try[Unit] = Try {
    val recoveredTop: (ProverNodes[D], Int) = storage.rollback(version).get
    avlProver = new BatchAVLProver(avlProver.keyLength, avlProver.valueLengthOpt, Some(recoveredTop))(avlProver.hf)
  }

  def checkTree(postProof: Boolean = false): Unit = avlProver.checkTree(postProof)
}

object PersistentBatchAVLProver {
  def create[D <: Digest, HF <: ThreadUnsafeHash[D]](avlBatchProver: BatchAVLProver[D, HF],
                                                     versionedStorage: VersionedAVLStorage[D],
                                                     paranoidChecks: Boolean = false
                                                    ): Try[PersistentBatchAVLProver[D, HF]] = Try {

    new PersistentBatchAVLProver[D, HF] {
      override var avlProver: BatchAVLProver[D, HF] = avlBatchProver
      override val storage: VersionedAVLStorage[D] = versionedStorage

      (storage.version match {
        case Some(ver) => rollback(ver).get
        case None => generateProof() //to initialize storage and clear prover's state
      }).ensuring { _ =>
        storage.version.get.sameElements(avlProver.digest) &&
          (!paranoidChecks || Try(avlProver.checkTree(true)).isSuccess)
      }
    }
  }
}