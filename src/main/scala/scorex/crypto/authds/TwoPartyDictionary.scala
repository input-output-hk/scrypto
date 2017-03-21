package scorex.crypto.authds

import scorex.crypto.authds.avltree.batch.Operation
import scorex.crypto.hash.CryptographicHash

import scala.util.Try

trait TwoPartyDictionary {

  /**
    * Run an operation, whether a lookup or a modification, against the tree
    *
    * @param operation - tree modification
    * @return modification proof
    */
  def run[O <: Operation](operation: O): Try[TwoPartyProof]

  /**
    * @return current digest of structure
    */
  def rootHash(): Array[Byte]
}

object TwoPartyDictionary {
  type Label = CryptographicHash#Digest
}