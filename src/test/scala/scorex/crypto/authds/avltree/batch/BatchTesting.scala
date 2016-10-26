package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree._

import scala.util.{Failure, Success, Try}

sealed trait BatchProvingResultSimple

case class BatchSuccessSimple(proofs: Seq[AVLModifyProof]) extends BatchProvingResultSimple


trait BatchProof

sealed trait BatchProvingResult

case class BatchSuccess(proof: BatchProof) extends BatchProvingResult

//todo: add reason, problematicModification: Modification
case class BatchFailure(error: Throwable)
  extends BatchProvingResultSimple with BatchProvingResult

class oldProver(tree: AVLTree[_]) extends UpdateF[AVLKey] {
  def applyBatchSimple(modifications: Seq[Modification]): BatchProvingResultSimple = {
    Modification.convert(modifications).foldLeft(Success(Seq()): Try[Seq[AVLModifyProof]]) { case (t, (k, uf)) =>
      t match {
        case Success(proofs) =>
          tree.modify(k, uf).map(proof => proofs :+ proof)
        case f@Failure(e) => f
      }
    } match {
      case Success(proofs) => BatchSuccessSimple(proofs)
      case Failure(e) => BatchFailure(e)
    }
  }

  def rootHash: Label = tree.rootHash()
}


class oldVerifier(digest: Label) extends UpdateF[AVLKey] {
  def verifyBatchSimple(modifications: Seq[Modification], batch: BatchSuccessSimple): Boolean = {
    require(modifications.size == batch.proofs.size)
    batch.proofs.zip(Modification.convert(modifications)).foldLeft(Some(digest): Option[Label]) {
      case (digestOpt, (proof, mod)) =>
        digestOpt.flatMap(digest => proof.verify(digest, mod._2))
    }.isDefined
  }

  def verifyBatchComprehensive(modifications: Seq[Modification], batch: BatchSuccess): Boolean = ???
}
