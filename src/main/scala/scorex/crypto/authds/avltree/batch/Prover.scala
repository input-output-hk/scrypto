package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree._
import scorex.utils.Random

import scala.util.{Failure, Success, Try}


sealed trait Modification

case class Insert(key: AVLKey, value: Array[Byte]) extends Modification

case class Update(key: AVLKey, value: Array[Byte]) extends Modification

case class Remove(key: AVLKey) extends Modification


sealed trait BatchProvingResultSimple

case class BatchSuccessSimple(proofs: Seq[AVLModifyProof]) extends BatchProvingResultSimple


trait BatchProof

sealed trait BatchProvingResult

case class BatchSuccess(proof: BatchProof) extends BatchProvingResult

//todo: add reason, problematicModification: Modification
case class BatchFailure(error: Throwable)
  extends BatchProvingResultSimple with BatchProvingResult

trait ADSUser extends UpdateF[Array[Byte]] {
  protected def convert(modifications: Seq[Modification]): Seq[(AVLKey, UpdateFunction)] =
    modifications.map { m =>
      m match {
        case Insert(key, value) => key -> ({ oldOpt => oldOpt match {
          case None => Success(Some(value))
          case Some(_) => Failure(new Exception("already exists"))
        }
        }: UpdateFunction)
        case Update(key, value) => key -> ({ oldOpt => oldOpt match {
          case None => Failure(new Exception("does not exist"))
          case Some(_) => Success(Some(value))
        }
        }: UpdateFunction)
        case Remove(key) => key -> ({ oldOpt => oldOpt match {
          case None => Failure(new Exception("does not exist"))
          case Some(_) => Success(None)
        }
        }: UpdateFunction)
      }
    }
}

class Prover(tree: AVLTree[_]) extends ADSUser {
  def applyBatchSimple(modifications: Seq[Modification]): BatchProvingResultSimple = {
    convert(modifications).foldLeft(Success(Seq()): Try[Seq[AVLModifyProof]]) { case (t, (k, uf)) =>
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

  def applyBatchComprehensive(modifications: Seq[Modification]): BatchProvingResult = {
    convert(modifications)
    ???
  }
}


class Verifier(digest: Label) extends ADSUser {
  def verifyBatchSimple(modifications: Seq[Modification], batch: BatchSuccessSimple): Boolean = {
    require(modifications.size == batch.proofs.size)
    batch.proofs.zip(convert(modifications)).foldLeft(Some(digest): Option[Label]) {
      case (digestOpt, (proof, mod)) =>
        digestOpt.flatMap(digest => proof.verify(digest, mod._2))
    }.isDefined
  }

  def verifyBatchComprehensive(modifications: Seq[Modification], batch: BatchSuccess): Boolean = ???
}

object BatchingPlayground extends App {

  val tree = new AVLTree(32)
  val digest0 = tree.rootHash()

  val prover = new Prover(tree)

  val m1 = Insert(Random.randomBytes(), Array.fill(8)(0: Byte))
  val m2 = Insert(Random.randomBytes(), Array.fill(8)(1: Byte))
  val m3 = Update(m1.key, Array.fill(8)(1: Byte))
  val modifications = Seq(m1, m2, m3)

  prover.applyBatchSimple(modifications) match {
    case bss: BatchSuccessSimple =>
      assert(new Verifier(digest0).verifyBatchSimple(modifications, bss))

      val m4 = Update(m2.key, Array.fill(8)(0: Byte))
      val wrongMods = Seq(m1, m2, m4)
      assert(new Verifier(digest0).verifyBatchSimple(wrongMods, bss))
    case bf: BatchFailure =>
      println(bf.error)
      assert(false)
  }
}