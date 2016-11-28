package scrypto.authds

import scala.util.Try

trait UpdateF[Value] {
  /**
    * Update functions takes Option[oldValue] and return Try[Option[newValue]]
    * Insert: None => Success(Some(newValue))
    * Update: Some(oldValue) => Success(Some(newValue))
    * Delete: Some(oldValue) => Success(None)
    * Return Failure() to ensure, if found value is not expected (e.g. no old value expected).
    */
  type UpdateFunction = Option[Value] => Try[Option[Value]]
}
