package scorex.crypto.authds

import scorex.crypto.authds.legacy.treap.Level
import scorex.crypto.hash._

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

  protected def dequeueRightLabel(): Digest = {
    i = i + 1
    Digest32 @@ proofSeq(i).asInstanceOf[ProofRightLabel].e
  }

  protected def dequeueLeftLabel(): Digest = {
    i = i + 1
    Digest32 @@ proofSeq(i).asInstanceOf[ProofLeftLabel].e
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
      case -1 => Balance @@ -1.toByte
      case 0 => Balance @@ 0.toByte
      case 1 => Balance @@ 1.toByte
    }
  }
}
