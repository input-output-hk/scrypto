package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.encode.Base58
import scorex.crypto.hash.CommutativeHash


case class SLProofSeq(height: Int, proofs: Seq[ProofToRecalculate]) extends SLProofI {

  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    def loop(rProofs: Seq[ProofToRecalculate], curRootHash: Digest, curHeight: Int): Boolean = rProofs.headOption match {
      case Some(proofToRecalculate) =>
        if (proofToRecalculate.proof.check(curRootHash)) {
          val (newRH, newLev) = ExtendedSLProof.recalculateProof(proofToRecalculate, curHeight)
          loop(rProofs.tail, newRH, newLev)
        } else false
      case None => true
    }
    loop(proofs, rootHash, height)
  }

  lazy val bytes: Array[Byte] = ???

  def isEmpty: Boolean = proofs.isEmpty
}



