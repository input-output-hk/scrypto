package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree.{AVLKey, AVLValue}

import scala.util.{Failure, Success}

sealed trait Modification {
  val key: AVLKey
}

case class Insert(key: AVLKey, value: Array[Byte]) extends Modification

case class Update(key: AVLKey, value: Array[Byte]) extends Modification

case class Remove(key: AVLKey) extends Modification

case class RemoveIfExists(key: AVLKey) extends Modification

object Modification extends UpdateF[AVLKey] {

  private def insertFunction(value: AVLValue) = {
    case None => Success(Some(value))
    case Some(_) => Failure(new Exception("already exists"))
  }: UpdateFunction

  private def updateFunction(value: AVLValue) = {
    case None => Failure(new Exception("does not exist"))
    case Some(_) => Success(Some(value))
  }: UpdateFunction

  private def removeFunction() = {
    case None => Failure(new Exception("does not exist"))
    case Some(_) => Success(None)
  }: UpdateFunction

  private def removeIfExistsFunction() = { // TODO: there must be a better syntax here -- someone with scala knowledge please fix
    case None => Success(None)
    case Some(_) => Success(None)
  }: UpdateFunction

  def convert(modifications: Seq[Modification]): Seq[(AVLKey, UpdateFunction)] = modifications.map(convert)

  // TODO: to demonstrated more rich examples, add "increase value" and "decrease value, failing if below 0 and deleting if 0"
  def convert(modification: Modification): (AVLKey, UpdateFunction) = {
    modification match {
      case Insert(key, value) => key -> insertFunction(value)
      case Update(key, value) => key -> updateFunction(value)
      case Remove(key) => key -> removeFunction()
      case RemoveIfExists(key) => key -> removeIfExistsFunction()
    }
  }
}

//TODO: remove
/*
object BatchTest extends App {
  val prover = new BatchAVLProver(keyLength = 1, valueLength = 8)
  val initRoot = prover.rootHash
  val initHeight = prover.rootHeight

  print(initHeight)

  val m1 = Insert(Array(1:Byte), Array.fill(8)(0:Byte))
  val m2 = Insert(Array(2:Byte), Array.fill(8)(0:Byte))

  prover.performOneModification(m1)
  prover.performOneModification(m2)
  val proof1 = prover.generateProof

  val m3 = Update(Array(1:Byte), Array.fill(8)(1:Byte))
  val m4 = Remove(Array(2:Byte))
  prover.performOneModification(m3)
  prover.performOneModification(m4)
  val proof2 = prover.generateProof
  val rootDeclared = prover.rootHash


  val verifier1 = new BatchAVLVerifier(initRoot, proof1, keyLength = 1, valueLength = 8)
  println(verifier1.performOneModification(m1))
  verifier1.performOneModification(m2)
  verifier1.digest match {
    case Some(root1) =>
      val verifier2 = new BatchAVLVerifier(root1, proof2, keyLength = 1, valueLength = 8)
      verifier2.performOneModification(m3)
      verifier2.performOneModification(m4)
      verifier2.digest match {
        case Some(root2) if root2.sameElements(rootDeclared) => println("declared root value and proofs are valid")
        case _ => println("second proof or declared root value  NOT valid")
      }
    case None =>
      println("first proof is invalid")
  }
}*/