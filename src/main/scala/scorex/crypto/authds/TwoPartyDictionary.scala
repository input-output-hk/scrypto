package scorex.crypto.authds

trait TwoPartyDictionary[Key, Value] {
  def modify(key: Key, updateFunction: Option[Value] => Value, toInsertIfNotFound: Boolean): TwoPartyProof[Key, Value]
  def rootHash(): Array[Byte]
}
