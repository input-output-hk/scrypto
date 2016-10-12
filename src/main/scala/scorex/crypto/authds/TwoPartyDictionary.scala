package scorex.crypto.authds

import scala.util.{Failure, Success, Try}

trait TwoPartyDictionary[Key, Value, ProofType <: TwoPartyProof[Key, Value]] {
  /**
    * Update authenticated data structure
    *
    * @param key - key to insert
    * @param updateFunction - function from old value to new one.
    * @return modification proof
    */
  def modify(key: Key, updateFunction: Option[Value] => Try[Value]): ProofType

  def lookup(key: Key): ProofType = modify(key, TwoPartyDictionary.lookupFunction[Value])

  /**
    * @return current digest of structure
    */
  def rootHash(): Array[Byte]


}

object TwoPartyDictionary {
  def lookupFunction[Value]: Option[Value] => Try[Value] = {
    case Some(oldValue) => Success(oldValue)
    case None => Failure(new Error("Just lookup"))
  }
}