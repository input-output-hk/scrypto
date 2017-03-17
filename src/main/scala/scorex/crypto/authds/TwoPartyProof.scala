package scorex.crypto.authds

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.avltree.batch.Operation

trait TwoPartyProof[Key, Value] extends ProofIterator {
  val key: Key
  val proofSeq: Seq[TwoPartyProofElement]

  /**
    * Verify proof according known digest and update function
    *
    * @param digest - current root hash of authenticated structure
    * @param operation - an operation to check correctness of
    * @return Some from new root hash if proof is valid or None if proof is not valid.
    */
  def verify[O <: Operation](digest: Label, operation: O): Option[Label]

}
