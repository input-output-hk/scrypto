package scorex.crypto.authds

import scorex.crypto.authds.avltree._
import scorex.crypto.authds.legacy.treap.Level

trait ProofIterator {
  private var i = -1

  protected def initializeIterator(): Unit = i = -1

  val proofSeq: Seq[TwoPartyProofElement]

  protected def dequeueValue(): ADValue = {
    i = i + 1
    ADValue @@ proofSeq(i).asInstanceOf[ProofValue].e
  }

  protected def dequeueKey(): ADKey = {
    i = i + 1
    ADKey @@ proofSeq(i).asInstanceOf[ProofKey].e
  }

  protected def dequeueNextLeafKey(): ADKey = {
    i = i + 1
    ADKey @@ proofSeq(i).asInstanceOf[ProofNextLeafKey].e
  }

  protected def dequeueRightLabel(): Label = {
    i = i + 1
    Label @@ proofSeq(i).asInstanceOf[ProofRightLabel].e
  }

  protected def dequeueLeftLabel(): Label = {
    i = i + 1
    Label @@ proofSeq(i).asInstanceOf[ProofLeftLabel].e
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
