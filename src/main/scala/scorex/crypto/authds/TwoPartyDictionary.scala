package scorex.crypto.authds

import scala.util.{Success, Try}

trait TwoPartyDictionary[Key, Value] {
  /**
    * Update authenticated data structure
    *
    * @param key - key to insert
    * @param updateFunction - function from old value to new one.
    * @return modification proof
    */
  def modify(key: Key, updateFunction: Option[Value] => Try[Value]): TwoPartyProof[Key, Value]

  def lookup(key: Key): TwoPartyProof[Key, Value] = modify(key, lookupFunction)

  /**
    * @return current digest of structure
    */
  def rootHash(): Array[Byte]

  private def lookupFunction: Option[Value] => Try[Value] = {
    case Some(oldValue) => Success(oldValue)
    case None => ???
  }
}
