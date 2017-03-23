package scorex.crypto.authds.avltree.batch

import com.google.common.primitives.Longs
import scorex.crypto.authds.avltree.{AVLKey, AVLValue}

import scala.util.{Failure, Success, Try}

case class Lookup(override val key: AVLKey) extends Operation {
  /**
    * Update functions takes Option[oldValue] and return Try[Option[newValue]]
    * For example:
    * Insert: None => Success(Some(newValue)), but Some(oldValue) => Failure()
    * Update: Some(oldValue) => Success(Some(newValue))
    * Delete: Some(oldValue) => Success(None), but None => Failure()
    * ConditionalUpdate: Some(oldValue) => Success(Some(newValue)) or Failure(), depending
    * on whether oldValue satisfied some desired conditions
    */
  override def updateFn: UpdateFunction = old => Success(old)
}

case object UnknownOperation extends Operation {
  override val key: AVLKey = Array.empty

  override def updateFn: UpdateFunction = old => Success(old)
}

trait Operation {
  val key: AVLKey
  type OldValue = Option[AVLValue]

  type NewValue = AVLValue

  type UpdateFunction = OldValue => Try[Option[NewValue]]

  /**
    * Update functions takes Option[oldValue] and return Try[Option[newValue]]
    * For example:
    * Insert: None => Success(Some(newValue)), but Some(oldValue) => Failure()
    * Update: Some(oldValue) => Success(Some(newValue))
    * Delete: Some(oldValue) => Success(None), but None => Failure()
    * ConditionalUpdate: Some(oldValue) => Success(Some(newValue)) or Failure(), depending
    * on whether oldValue satisfied some desired conditions
    */
  def updateFn: UpdateFunction
}

case class Insert(key: AVLKey, value: Array[Byte]) extends Operation {
  override def updateFn: UpdateFunction = {
    case None => Success(Some(value))
    case Some(_) => Failure(new Exception("already exists"))
  }: UpdateFunction
}

case class Update(key: AVLKey, value: Array[Byte]) extends Operation {
  override def updateFn: UpdateFunction = {
    case None => Failure(new Exception("does not exist"))
    case Some(_) => Success(Some(value))
  }: UpdateFunction
}

case class InsertOrUpdate(key: AVLKey, value: Array[Byte]) extends Operation {
  override def updateFn: UpdateFunction = (_ => Success(Some(value))): UpdateFunction
}


case class Remove(key: AVLKey) extends Operation {
  override def updateFn: UpdateFunction = {
    case None => Failure(new Exception("does not exist"))
    case Some(_) => Success(None)
  }: UpdateFunction
}

case class RemoveIfExists(key: AVLKey) extends Operation {
  override def updateFn: UpdateFunction = (_ => Success(None)): UpdateFunction
}

/**
  * If the key exists in the tree, add delta to its value, fail if
  * the result is negative, and remove the key if the result is equal to 0.
  * If the key does not exist in the tree, treat it as if its value is 0:
  * insert the key with value delta if delta is positive,
  * fail if delta is negative, and do nothing if delta is 0.
  */
case class UpdateLongBy(key: AVLKey, delta: Long) extends Operation {
  override def updateFn: UpdateFunction = {
    case m if delta == 0 => Success(m)
    case None if delta > 0 => Success(Some(Longs.toByteArray(delta)))
    case None if delta < 0 => Failure(new Exception("Trying to decrease non-existing value"))
    case Some(oldV) =>
      val newVal = Math.addExact(Longs.fromByteArray(oldV), delta)
      if (newVal == 0) {
        Success(None)
      } else if (newVal > 0) {
        Success(Some(Longs.toByteArray(newVal)))
      } else {
        Failure(new Exception("New value is negative"))
      }
  }: UpdateFunction
}