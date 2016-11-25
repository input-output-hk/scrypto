package scrypto.authds

import scrypto.hash.CryptographicHash

import scala.util.{Failure, Success, Try}

trait TwoPartyDictionary[Key, Value, ProofType <: TwoPartyProof[Key, Value]] extends UpdateF[Value] {

  /**
    * Update authenticated data structure
    *
    * @param key - key to insert
    * @param updateFunction - function from old value to new one.
    * @return modification proof
    */
  def modify(key: Key, updateFunction: UpdateFunction): Try[ProofType]

  def lookup(key: Key): Try[ProofType] = modify(key, TwoPartyDictionary.lookupFunction[Value])

  def remove(key: Key): Try[ProofType] = modify(key, TwoPartyDictionary.removeFunction[Value])

  /**
    * @return current digest of structure
    */
  def rootHash(): Array[Byte]


}

object TwoPartyDictionary {
  type Label = CryptographicHash#Digest

  def removeFunction[Value]: Option[Value] => Try[Option[Value]] = {
    case Some(v) => Success(None)
    case None => Failure(new Error("Key not found"))
  }

  def existenceLookupFunction[Value]: Option[Value] => Try[Option[Value]] = {
    case Some(v) => Success(Some(v))
    case None => Failure(new Error("Key not found"))
  }

  def nonExistenceLookupFunction[Value]: Option[Value] => Try[Option[Value]] = {
    case Some(v) => Failure(new Error("Key found"))
    case None => Success(None)
  }

  def lookupFunction[Value]: Option[Value] => Try[Option[Value]] = { x: Option[Value] => Success(x) }
}