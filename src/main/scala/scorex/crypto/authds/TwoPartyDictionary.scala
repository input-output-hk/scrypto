package scorex.crypto.authds

import scala.util.Try

trait TwoPartyDictionary[Key, Value] {
  def modify(key: Key, updateFunction: Option[Value] => Try[Value]): TwoPartyProof[Key, Value]
  def rootHash(): Array[Byte]
}
