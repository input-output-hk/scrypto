package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.{ADDigest, ADKey, ADValue}
import scorex.crypto.hash.ThreadUnsafeHash

import scala.util.Try

abstract class PersistentBatchAVLProver[HF <: ThreadUnsafeHash]{

  var avlProver: BatchAVLProver[HF]
  val storage: VersionedAVLStorage

  def digest: Array[Byte] = avlProver.digest

  def height: Int = avlProver.rootNodeHeight

  def prover(): BatchAVLProver[HF] = avlProver

  def unauthenticatedLookup(key: ADKey): Option[ADValue] = avlProver.unauthenticatedLookup(key)

  def performOneOperation(operation: Operation): Try[Option[ADValue]] = avlProver.performOneOperation(operation)

  //side effect: avlProver modifies itself
  def generateProof(): Array[Byte] = {
    storage.update(avlProver).get
    avlProver.generateProof()
  }

  def rollback(version: ADDigest): Try[Unit] = Try {
    val recoveredTop: (ProverNodes, Int) = storage.rollback(version).get
    avlProver = new BatchAVLProver(avlProver.keyLength, avlProver.valueLengthOpt, Some(recoveredTop))(avlProver.hf)
  }

  def checkTree(postProof: Boolean = false): Unit = avlProver.checkTree(postProof)
}

object PersistentBatchAVLProver {
  def create[HF <: ThreadUnsafeHash](avlBatchProver: BatchAVLProver[HF],
                                     versionedStorage: VersionedAVLStorage,
                                     paranoidChecks: Boolean = false
                                    ): Try[PersistentBatchAVLProver[HF]] = Try {

    new PersistentBatchAVLProver[HF] {
      override var avlProver: BatchAVLProver[HF] = avlBatchProver
      override val storage: VersionedAVLStorage = versionedStorage

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