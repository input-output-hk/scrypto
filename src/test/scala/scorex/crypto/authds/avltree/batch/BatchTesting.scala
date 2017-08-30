package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds._
import scorex.crypto.authds.legacy.avltree.{AVLModifyProof, AVLTree}

import scala.collection.mutable.ArrayBuffer
import scala.util.{Failure, Success, Try}

sealed trait BatchProvingResultSimple

case class BatchSuccessSimple(proofs: Seq[AVLModifyProof]) extends BatchProvingResultSimple


trait BatchProof

sealed trait BatchProvingResult

case class BatchSuccess(proof: BatchProof) extends BatchProvingResult

case class BatchFailure(error: Throwable, reason: Operation)
  extends Exception with BatchProvingResultSimple with BatchProvingResult

class LegacyProver(tree: AVLTree[_]) {
  def applyBatchSimple(modifications: Seq[Operation]): BatchProvingResultSimple = {
    applyUpdates(modifications)
  }

  def applyUpdates(modifications: Seq[Operation]): BatchProvingResultSimple = Try {
    val aggregatedProofs = modifications.foldLeft(ArrayBuffer[AVLModifyProof]()) { (a, m) =>
      tree.run(m) match {
        case Success(proof) => proof +: a
        case Failure(e) => throw BatchFailure(e, m)
      }
    }
    BatchSuccessSimple(aggregatedProofs)
  } match {
    case Success(p) => p
    case Failure(e: BatchFailure) => e
    case Failure(e) => BatchFailure(e, UnknownModification)
  }

  def rootHash: ADDigest = tree.rootHash()
}


class LegacyVerifier(digest: ADDigest) {
  def verifyBatchSimple(operations: Seq[Modification], batch: BatchSuccessSimple): Boolean = {
    require(operations.size == batch.proofs.size)
    batch.proofs.zip(operations).foldLeft(Some(digest): Option[ADDigest]) {
      case (digestOpt, (proof, op)) =>
        digestOpt.flatMap(digest => proof.verify(digest, op))
    }.isDefined
  }

}
