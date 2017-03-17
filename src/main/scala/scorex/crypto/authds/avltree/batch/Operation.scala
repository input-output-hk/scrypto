package scorex.crypto.authds.avltree.batch

import com.google.common.primitives.Longs
import scorex.crypto.authds.avltree.{AVLKey, AVLValue}

import scala.util.{Failure, Success, Try}

trait Operation {
  val key: AVLKey
}

trait Lookup extends Operation

case class LookupExisting(override val key: AVLKey) extends Lookup

case class LookupNonExisting(override val key: AVLKey) extends Lookup

trait Modification extends Operation {
  type OldValue = Option[AVLValue]

  type NewValue = AVLValue

  type UpdateFunction = OldValue => Try[Option[NewValue]]

  /**
    * Update functions takes Option[oldValue] and return Try[Option[newValue]]
    * Insert: None => Success(Some(newValue))
    * Update: Some(oldValue) => Success(Some(newValue))
    * Delete: Some(oldValue) => Success(None)
    * Return Failure() to ensure, if found value is not expected (e.g. no old value expected).
    */
  def updateFn: UpdateFunction
}

case class Insert(key: AVLKey, value: Array[Byte]) extends Modification {
  override def updateFn: UpdateFunction = {
    case None => Success(Some(value))
    case Some(_) => Failure(new Exception("already exists"))
  }: UpdateFunction
}

case class Update(key: AVLKey, value: Array[Byte]) extends Modification {
  override def updateFn: UpdateFunction = {
    case None => Failure(new Exception("does not exist"))
    case Some(_) => Success(Some(value))
  }: UpdateFunction
}

case class InsertOrUpdate(key: AVLKey, value: Array[Byte]) extends Modification {
  override def updateFn: UpdateFunction = (_ => Success(Some(value))): UpdateFunction
}


case class Remove(key: AVLKey) extends Modification {
  override def updateFn: UpdateFunction = {
    case None => Failure(new Exception("does not exist"))
    case Some(_) => Success(None)
  }: UpdateFunction
}

case class RemoveIfExists(key: AVLKey) extends Modification {
  override def updateFn: UpdateFunction = (_ => Success(None)): UpdateFunction
}

/**
  * Update existing value by delta, insert if old value is not exists and positive, remove if remaining is 0,
  * fails on negative new value
  */
case class UpdateLongBy(key: AVLKey, delta: Long) extends Modification {
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