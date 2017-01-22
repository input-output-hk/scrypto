package scorex.crypto.authds.avltree.batch

import com.google.common.primitives.Longs
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree.{AVLKey, AVLValue}

import scala.util.{Failure, Success, Try}

sealed trait Modification {
  val key: AVLKey
}

case class Insert(key: AVLKey, value: Array[Byte]) extends Modification

case class Update(key: AVLKey, value: Array[Byte]) extends Modification

case class Remove(key: AVLKey) extends Modification

case class RemoveIfExists(key: AVLKey) extends Modification

case class UpdateLongBy(key: AVLKey, value: Long) extends Modification

object Modification extends UpdateF[AVLValue] {

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

  /**
    * Update existing value by delta, insert if old value is not exists and positive, remove is remaining is 0,
    * fails on negative new value
    */
  private def updateDelta(delta: Long) = {
    case m if delta == 0 => Success(m)
    case None if delta > 0 => Success(Some(Longs.toByteArray(delta)))
    case None if delta < 0 => Failure(new Exception("Trying to decrease non-existing value"))
    case Some(oldV) =>
      val newVal = Math.addExact(Longs.fromByteArray(oldV), delta)
      if (newVal == 0) {
        Success(None)  //todo: is it intended to remove an element if its value is 0?
      } else if (newVal > 0) {
        Success(Some(Longs.toByteArray(newVal)))
      } else {
        Failure(new Exception("New value is negative"))
      }
  }: UpdateFunction

  private def removeIfExistsFunction() = (_ => Success(None)): UpdateFunction

  def convert(modifications: Seq[Modification]): Seq[(AVLKey, UpdateFunction)] = modifications.map(convert)

  def convert(modification: Modification): (AVLKey, UpdateFunction) = {
    modification match {
      case Insert(key, value) => key -> insertFunction(value)
      case Update(key, value) => key -> updateFunction(value)
      case Remove(key) => key -> removeFunction()
      case RemoveIfExists(key) => key -> removeIfExistsFunction()
      case UpdateLongBy(key, value) => key -> updateDelta(value)
    }
  }
}