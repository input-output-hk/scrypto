package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree._
import scorex.utils.Random

import scala.util.{Failure, Success, Try}

import scorex.crypto.authds._
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray

import scala.util.{Failure, Success, Try}
import scala.collection.mutable



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

class oldProver(tree: AVLTree[_]) extends ADSUser {
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
  def rootHash = tree.rootHash
}


class oldVerifier(digest: Label) extends ADSUser {
  def verifyBatchSimple(modifications: Seq[Modification], batch: BatchSuccessSimple): Boolean = {
    require(modifications.size == batch.proofs.size)
    batch.proofs.zip(convert(modifications)).foldLeft(Some(digest): Option[Label]) {
      case (digestOpt, (proof, mod)) =>
        digestOpt.flatMap(digest => proof.verify(digest, mod._2))
    }.isDefined
  }

  def verifyBatchComprehensive(modifications: Seq[Modification], batch: BatchSuccess): Boolean = ???
}

object BatchingPlayground extends App with ADSUser {

  val tree = new AVLTree(32)
  val digest0 = tree.rootHash()

  val oldProver = new oldProver(tree)

  val m11 = Insert(Array.fill(32)(5:Byte), Array.fill(8)(0: Byte))
  val m12 = Insert(Array.fill(32)(7:Byte), Array.fill(8)(1: Byte))
  val m13 = Update(m11.key, Array.fill(8)(1: Byte))
  val modifications1 = Seq(m11, m12, m13)
  val m21 = Insert(Array.fill(32)(1:Byte), Array.fill(8)(3: Byte))
  val m22 = Insert(Array.fill(32)(3:Byte), Array.fill(8)(7: Byte))
  val m23 = Update(m22.key, Array.fill(8)(15: Byte))
  val modifications2 = Seq(m21, m22, m23)


  oldProver.applyBatchSimple(modifications1) match {
    case bss: BatchSuccessSimple =>
      assert(new oldVerifier(digest0).verifyBatchSimple(modifications1, bss))

      val m4 = Insert(Random.randomBytes(), Array.fill(8)(1: Byte))
    // val wrongMods = Seq(m1, m2, m4)
    // assert(!new oldVerifier(digest0).verifyBatchSimple(wrongMods, bss)//)
    case bf: BatchFailure =>
      println(bf.error)
      assert(false)
  }
  
  val newProver = new NewBatchProver(32)
  if (newProver.rootHash sameElements digest0)
    print("Two prover's digests match before modifications1 ")
  else
    print("ERROR Two prover's digests do not match before modifications1 ")   
  println(digest0(0))

  convert(modifications1) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
  val p1 = newProver.generateProof
  if (newProver.rootHash sameElements oldProver.rootHash)
    println("Two prover's digests match after modifications1")
  else
    println("ERROR Two prover's digests do not match after modifications1")   
  var newVerifier = new NewBatchVerifier(digest0, p1)
  newVerifier.digest match {
    case None =>
      println("ERROR VERIFICATION FAILED TO CONSTRUCT THE TREE")
    case Some(d) =>
      if (d sameElements digest0)
        println("Tree successfully built")
      else
        println("ERROR BUILT TREE, WRONG DIGEST")
  }

  print("Directions length ")
  println(p1.directions.length)
  convert(modifications1) foreach (m => newVerifier.verifyOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
  newVerifier.digest match {
    case None =>
      println("ERROR VERIFICATION FAIL")
    case Some(d) =>
      if (d sameElements newProver.rootHash)
        println("Success")
      else {
        println("ERROR Nonmatching Digests between prover and verifier")
        if (d sameElements oldProver.rootHash) println("old root hash is good, though!")
        else println ("they all suck!")
      }
  }
  
  val digest1 = newProver.rootHash
  convert(modifications2) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
  val p2 = newProver.generateProof
  newVerifier = new NewBatchVerifier(digest1, p2)
  newVerifier.digest match {
    case None =>
      println("ERROR VERIFICATION FAILED TO CONSTRUCT THE TREE")
    case Some(d) =>
      if (d sameElements digest1)
        println("Tree successfully built")
      else
        println("ERROR BUILT TREE, WRONG DIGEST")
  }

  print("Directions length ")
  println(p2.directions.length)
  convert(modifications2) foreach (m => newVerifier.verifyOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
  newVerifier.digest match {
    case None =>
      println("ERROR VERIFICATION FAIL")
    case Some(d) =>
      if (d sameElements newProver.rootHash)
        println("Success")
      else {
        println("ERROR Nonmatching Digests between prover and verifier")
        if (d sameElements oldProver.rootHash) println("old root hash is good, though!")
        else println ("they all suck!")
      }
  }

}