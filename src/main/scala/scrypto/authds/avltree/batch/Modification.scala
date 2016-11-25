package scrypto.authds.avltree.batch

import scrypto.authds.UpdateF
import scrypto.authds.avltree._

import scala.util.{Failure, Success}

sealed trait Modification {
  val key: AVLKey
}

case class Insert(key: AVLKey, value: Array[Byte]) extends Modification

case class Update(key: AVLKey, value: Array[Byte]) extends Modification

case class Remove(key: AVLKey) extends Modification

object Modification extends UpdateF[AVLKey] {

  def convert(modifications: Seq[Modification]): Seq[(AVLKey, UpdateFunction)] = modifications.map(convert)

  def convert(modification: Modification): (AVLKey, UpdateFunction) = {
    modification match {
      case Insert(key, value) => key -> ({
        case None => Success(Some(value))
        case Some(_) => Failure(new Exception("already exists"))
      }: UpdateFunction)
      case Update(key, value) => key -> ({
        case None => Failure(new Exception("does not exist"))
        case Some(_) => Success(Some(value))
      }: UpdateFunction)
      case Remove(key) => key -> ({
        case None => Failure(new Exception("does not exist"))
        case Some(_) => Success(None)
      }: UpdateFunction)
    }
  }
}