package scrypto.authds

import scrypto.authds.TwoPartyDictionary.Label

trait TwoPartyProof[Key, Value] extends UpdateF[Value] with ProofIterator {
  val key: Key
  val proofSeq: Seq[TwoPartyProofElement]

  /**
    * Verify proof according known digest and update function
    *
    * @param digest - current root hash of authenticated structure
    * @param updateFunction - function from old value to new one
    * @return Some from new root hash if proof is valid or None if proof is not valid.
    */
  def verify(digest: Label, updateFunction: UpdateFunction): Option[Label]

}
