package scorex.crypto.authds

import scorex.crypto.authds.avltree.batch.Operation
import scorex.crypto.hash.CryptographicHash

import scala.util.Try

trait TwoPartyDictionary[Key, Value, ProofType <: TwoPartyProof[Key, Value]] {

  /**
    * Update authenticated data structure
    *
    * @param modification - tree modification
    * @return modification proof
    */
  def modify[M <: Operation](modification: M): Try[ProofType]

  //todo: remove?

 // def lookup(key: Key): Try[ProofType] = modify(key, TwoPartyDictionary.lookupFunction[Value])

  //def remove(key: Key): Try[ProofType] = modify(Remove(key))

  /**
    * @return current digest of structure
    */
  def rootHash(): Array[Byte]
}

object TwoPartyDictionary {
  type Label = CryptographicHash#Digest
}