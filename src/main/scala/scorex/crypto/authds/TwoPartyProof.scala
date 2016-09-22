package scorex.crypto.authds

import scala.collection.mutable


trait TwoPartyProof[Key, Value] {
  type Label = Array[Byte]
  val key: Key
  val proofSeq: Seq[TwoPartyProofElement]
  def verify(digest: Label, updateFunction: Option[Value] => Value, toInsertIfNotFound: Boolean = true): Option[Label]

  def dequeueValue(proof: mutable.Queue[TwoPartyProofElement]): Array[Byte] = {
    proof.dequeue().asInstanceOf[ProofValue].e
  }

  def dequeueKey(proof: mutable.Queue[TwoPartyProofElement]): Array[Byte] = {
    proof.dequeue().asInstanceOf[ProofKey].e
  }

  def dequeueNextLeafKey(proof: mutable.Queue[TwoPartyProofElement]): Array[Byte] = {
    proof.dequeue().asInstanceOf[ProofNextLeafKey].e
  }

  def dequeueRightLabel(proof: mutable.Queue[TwoPartyProofElement]): Label = {
    proof.dequeue().asInstanceOf[ProofRightLabel].e
  }

  def dequeueLeftLabel(proof: mutable.Queue[TwoPartyProofElement]): Label = {
    proof.dequeue().asInstanceOf[ProofLeftLabel].e
  }

  def dequeueDirection(proof: mutable.Queue[TwoPartyProofElement]): Direction = {
    proof.dequeue().asInstanceOf[ProofDirection].direction
  }

  def dequeueLevel(proof: mutable.Queue[TwoPartyProofElement]): Level = {
    proof.dequeue().asInstanceOf[ProofLevel].e
  }

  def dequeueBalance(proof: mutable.Queue[TwoPartyProofElement]): Int = {
    proof.dequeue().bytes(0) match {
      case 0 => -1
      case 1 => 0
      case 2 => 1
    }
  }
}
