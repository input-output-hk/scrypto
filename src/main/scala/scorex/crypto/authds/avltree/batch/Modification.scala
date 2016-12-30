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