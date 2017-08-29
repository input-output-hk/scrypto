package scorex.crypto.authds

import scorex.crypto.authds.avltree.batch.Modification

trait TwoPartyProof extends ProofIterator {
  val key: ADKey
  val proofSeq: Seq[TwoPartyProofElement]

  /**
    * Verify proof according known digest and update function
    *
    * @param digest   - current root hash of authenticated structure
    * @param updateFn - a modification to check correctness of
    * @return Some from new root hash if proof is valid or None if proof is not valid.
    */
  def verify(digest: Label, updateFn: Modification#UpdateFunction): Option[Label]

  def verify(digest: Label, modification: Modification): Option[Label] = verify(digest, modification.updateFn)
}
