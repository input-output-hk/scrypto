package scorex.crypto.authds

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.avltree.batch.Modification

trait TwoPartyProof[Key, Value] extends ProofIterator {
  val key: Key
  val proofSeq: Seq[TwoPartyProofElement]

  def verify[M <: Modification](digest: Label, modification:M): Option[Label] =
    verify(digest, modification.updateFn)

  /**
    * Verify proof according known digest and update function
    *
    * @param digest - current root hash of authenticated structure
    * @param updateFunction - function from old value to new one
    * @return Some from new root hash if proof is valid or None if proof is not valid.
    */
  def verify(digest: Label, updateFunction: Modification#UpdateFunction): Option[Label]

}
