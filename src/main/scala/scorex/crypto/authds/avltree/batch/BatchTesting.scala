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



sealed trait Modification {val key: AVLKey}

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
  //spaceBenchmarks
  variousTests

  // TODO: Add a test that modifies directions and sees verifier reject

  def spaceBenchmarks {
    val newProver = new BatchAVLProver()
  
    val numMods = 1024*1024
 
    val mod = new Array[Modification](1)
    for (i <-0 until numMods) {
      mod(0)=(Insert(Random.randomBytes(), Random.randomBytes(8)))
      convert(mod) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
      if (i%10000 == 0)
        println(i)
    }
    val pf = newProver.generateProof.toArray
    println(pf.length)

    var j = 1
    // Init j
    while (j < 1000000) // TODO: can't run this test -- runs out of heap
     j = j*2
    j = j/2
    
    
    while (j<1000000) {
      for (i <-0 until j) {
        mod(0)=(Insert(Random.randomBytes(), Random.randomBytes(8)))
        convert(mod) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
      }
      print("j = ")
      println(j)
      val pf = newProver.generateProof.toArray
      print("proof length ")
      println(pf.length)
      print("proof length per mod ")
      println(pf.length/j)
      j=j*2
    }
  }

  def variousTests {
    val tree = new AVLTree(32)
    var digest = tree.rootHash()
    val oldProver = new oldProver(tree)
   
    val newProver = new BatchAVLProver()
    assert (newProver.rootHash sameElements digest)
   
    val numMods = 10000
   
    val mods = new Array[Modification](numMods)
    mods(0) = Insert(Random.randomBytes(), Random.randomBytes(8))
 
    var numInserts = 0
    for (i <- 1 until numMods) {
      if((Random.randomBytes(1))(0).toInt>0) { // with prob ~.5 insert a new one, with prob ~.5 update an existing one
        mods(i) = Insert(Random.randomBytes(), Random.randomBytes(8))
        numInserts+=1
      }
      else {
        val j = Random.randomBytes(3)
        mods(i) = Update(mods((j(0).toInt.abs+j(1).toInt.abs*128+j(2).toInt.abs*128*128) % i).key, Random.randomBytes(8))
      }
    }
   
    var i = 0
    var firstTime = true
    while (i<numMods) {
      var j = if (firstTime) {firstTime=false; 0} else i+(Random.randomBytes(1))(0).toInt.abs
      if (j>numMods) j = numMods
       println(j)
      val currentMods = new scala.collection.mutable.ArrayBuffer[Modification](j-i)
      while(i<j) {
        currentMods += mods(i)      
        i+=1
      }

      oldProver.applyBatchSimple(currentMods) match {
        case bss: BatchSuccessSimple =>
          assert(new oldVerifier(digest).verifyBatchSimple(currentMods, bss))
        case bf: BatchFailure =>
          println(bf.error)
          assert(false)
      }
 
      convert(currentMods) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
      val pf = newProver.generateProof.toArray
     
      println(pf.length)
   
      val newVerifier = new BatchAVLVerifier(digest, pf)
      newVerifier.digest match {
        case None =>
          println("ERROR VERIFICATION FAILED TO CONSTRUCT THE TREE")
          assert(false)
        case Some(d) =>
          assert (d sameElements digest) // Tree built successfully
      }
     
      digest = oldProver.rootHash
      assert (newProver.rootHash sameElements digest)
      convert(currentMods) foreach (m => newVerifier.verifyOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
      newVerifier.digest match {
        case None =>
          println("ERROR VERIFICATION FAIL")
          assert(false)
        case Some(d) =>
          assert (d sameElements digest)
      }
    }
    print("NumInserts = ")
    println(numInserts)
  }
}
   