package scrypto.authds.avltree.batch

import scrypto.authds.TwoPartyDictionary.Label
import scrypto.authds.UpdateF
import scrypto.authds.avltree._

import scala.collection.mutable.ArrayBuffer
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
    applyUpdates(Modification.convert(modifications))
  }

  def applyUpdates(modifications: Seq[(AVLKey, UpdateFunction)]): BatchProvingResultSimple = Try {
    val agregatedProofs: ArrayBuffer[AVLModifyProof] = ArrayBuffer()
    modifications.foreach { case (k, uf) =>
      tree.modify(k, uf) match {
        case Success(proof) =>
          agregatedProofs += proof
        case Failure(e) => throw e
      }
    }
    BatchSuccessSimple(agregatedProofs)
  } match {
    case Success(p) => p
    case Failure(e) => BatchFailure(e)
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
