package scorex.crypto.authds

import scala.collection.mutable
import scala.util.Try


trait TwoPartyProof[Key, Value] {
  type Label = Array[Byte]
  val key: Key
  val proofSeq: Seq[TwoPartyProofElement]

  /**
    * Verify proof according known digest and update function
    *
    * @param digest - current root hash of authenticated structure
    * @param updateFunction - function from old value to new one
    * @return Some from new root hash if proof is valid or None if proof is not valid.
    */
  def verify(digest: Label, updateFunction: Option[Value] => Try[Value]): Option[Label]

  protected def dequeueValue(proof: mutable.Queue[TwoPartyProofElement]): Array[Byte] = {
    proof.dequeue().asInstanceOf[ProofValue].e
  }

  protected def dequeueKey(proof: mutable.Queue[TwoPartyProofElement]): Array[Byte] = {
    proof.dequeue().asInstanceOf[ProofKey].e
  }

  protected def dequeueNextLeafKey(proof: mutable.Queue[TwoPartyProofElement]): Array[Byte] = {
    proof.dequeue().asInstanceOf[ProofNextLeafKey].e
  }

  protected def dequeueRightLabel(proof: mutable.Queue[TwoPartyProofElement]): Label = {
    proof.dequeue().asInstanceOf[ProofRightLabel].e
  }

  protected def dequeueLeftLabel(proof: mutable.Queue[TwoPartyProofElement]): Label = {
    proof.dequeue().asInstanceOf[ProofLeftLabel].e
  }

  protected def dequeueDirection(proof: mutable.Queue[TwoPartyProofElement]): Direction = {
    proof.dequeue().asInstanceOf[ProofDirection].direction
  }

  protected def dequeueLevel(proof: mutable.Queue[TwoPartyProofElement]): Level = {
    proof.dequeue().asInstanceOf[ProofLevel].e
  }

  protected def dequeueBalance(proof: mutable.Queue[TwoPartyProofElement]): Int = {
    proof.dequeue().bytes(0) match {
      case -1 => -1
      case 0 => 0
      case 1 => 1
    }
  }
}
