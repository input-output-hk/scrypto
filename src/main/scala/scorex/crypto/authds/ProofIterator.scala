package scorex.crypto.authds

import scorex.crypto.authds.TwoPartyDictionary._
import scorex.crypto.authds.avltree._

trait ProofIterator {
  private var i = -1

  protected def initializeIterator(): Unit = i = -1

  val proofSeq: Seq[TwoPartyProofElement]

  protected def dequeueValue(): Array[Byte] = {
    i = i + 1
    proofSeq(i).asInstanceOf[ProofValue].e
  }

  protected def dequeueKey(): Array[Byte] = {
    i = i + 1
    proofSeq(i).asInstanceOf[ProofKey].e
  }

  protected def dequeueNextLeafKey(): Array[Byte] = {
    i = i + 1
    proofSeq(i).asInstanceOf[ProofNextLeafKey].e
  }

  protected def dequeueRightLabel(): Label = {
    i = i + 1
    proofSeq(i).asInstanceOf[ProofRightLabel].e
  }

  protected def dequeueLeftLabel(): Label = {
    i = i + 1
    proofSeq(i).asInstanceOf[ProofLeftLabel].e
  }

  protected def dequeueDirection(): Direction = {
    i = i + 1
    proofSeq(i).asInstanceOf[ProofDirection].direction
  }

  protected def dequeueLevel(): Level = {
    i = i + 1
    proofSeq(i).asInstanceOf[ProofLevel].e
  }

  protected def dequeueBalance(): Balance = {
    i = i + 1
    proofSeq(i).bytes(0) match {
      case -1 => -1: Byte
      case 0 => 0: Byte
      case 1 => 1: Byte
    }
  }

}
