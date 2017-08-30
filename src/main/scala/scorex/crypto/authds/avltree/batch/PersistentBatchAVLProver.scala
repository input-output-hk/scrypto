package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds._
import scorex.crypto.hash._

import scala.util.Try

abstract class PersistentBatchAVLProver[T<: Digest, HF <: ThreadUnsafeHash[T]]{

  var avlProver: BatchAVLProver[T, HF]
  val storage: VersionedAVLStorage[T]

  def digest: ADDigest = avlProver.digest

  def height: Int = avlProver.rootNodeHeight

  def prover(): BatchAVLProver[T, HF] = avlProver

  def unauthenticatedLookup(key: ADKey): Option[ADValue] = avlProver.unauthenticatedLookup(key)

  def performOneOperation(operation: Operation): Try[Option[ADValue]] = avlProver.performOneOperation(operation)

  //side effect: avlProver modifies itself
  def generateProof(): ADProof = {
    storage.update(avlProver).get
    avlProver.generateProof()
  }

  def rollback(version: ADDigest): Try[Unit] = Try {
    val recoveredTop: (ProverNodes[T], Int) = storage.rollback(version).get
    avlProver = new BatchAVLProver(avlProver.keyLength, avlProver.valueLengthOpt, Some(recoveredTop))(avlProver.hf)
  }

  def checkTree(postProof: Boolean = false): Unit = avlProver.checkTree(postProof)
}

object PersistentBatchAVLProver {
  def create[T <: Digest, HF <: ThreadUnsafeHash[T]](avlBatchProver: BatchAVLProver[T, HF],
                                     versionedStorage: VersionedAVLStorage[T],
                                     paranoidChecks: Boolean = false
                                    ): Try[PersistentBatchAVLProver[T, HF]] = Try {

    new PersistentBatchAVLProver[T, HF] {
      override var avlProver: BatchAVLProver[T, HF] = avlBatchProver
      override val storage: VersionedAVLStorage[T] = versionedStorage

      (if (storage.nonEmpty) {
        rollback(storage.version).get
      } else {
        generateProof() //to save prover's tree into database and clear its state
      }).ensuring{_ =>
        storage.version.sameElements(avlProver.digest) &&
          (!paranoidChecks || Try(avlProver.checkTree(true)).isSuccess)
      }
    }
  }
}