package scorex.crypto.authds.sltree

import scorex.crypto.authds._
import scorex.crypto.hash.CryptographicHash
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.Try

sealed trait SLTProof {
  val key: SLTKey

  def dequeueValue(proof: mutable.Queue[SLTProofElement]): SLTValue = {
    proof.dequeue().asInstanceOf[ProofValue].e
  }

  def dequeueKey(proof: mutable.Queue[SLTProofElement]): SLTKey = {
    proof.dequeue().asInstanceOf[ProofKey].e
  }

  def dequeueRightLabel(proof: mutable.Queue[SLTProofElement]): Label = {
    proof.dequeue().asInstanceOf[ProofRightLabel].e
  }

  def dequeueLeftLabel(proof: mutable.Queue[SLTProofElement]): Label = {
    proof.dequeue().asInstanceOf[ProofLeftLabel].e
  }

  def dequeueLevel(proof: mutable.Queue[SLTProofElement]): Int = {
    proof.dequeue().asInstanceOf[SLTProofLevel].e
  }
}

case class SLTLookupProof(key: SLTKey, proofSeq: Seq[SLTProofElement])(implicit hf: CryptographicHash)
  extends SLTProof {

  def verify(digest: Label): Option[SLTValue] = Try {
    val proof: mutable.Queue[SLTProofElement] = mutable.Queue(proofSeq: _*)
    def verifyLookupRecursive(): (Label, Option[SLTValue]) = {
      val nKey = dequeueKey(proof)
      val nValue = dequeueValue(proof)
      val nLevel = dequeueLevel(proof)
      ByteArray.compare(key, nKey) match {
        case 0 =>
          val nLeft = dequeueLeftLabel(proof)
          val nRight = dequeueRightLabel(proof)
          val n = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
          (n.label, Some(n.value))
        case o if o < 0 =>
          val nRight = dequeueRightLabel(proof)
          if (proof.isEmpty) {
            val nLeft = LabelOfNone
            val n = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            (n.computeLabel, None)
          } else {
            val (nLeft, v) = verifyLookupRecursive()
            val n = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            (n.computeLabel, v)
          }
        case _ =>
          val nLeft = dequeueLeftLabel(proof)
          if (proof.isEmpty) {
            val nRight = LabelOfNone
            val n = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            (n.computeLabel, None)
          } else {
            val (nRight, v) = verifyLookupRecursive()
            val n = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            (n.computeLabel, v)
          }
      }
    }
    val (h, v) = verifyLookupRecursive()
    if (h sameElements digest) v else None
  }.getOrElse(None)

}

trait SLTModifyingProof extends SLTProof {
  def verify(digest: Label, updateFunction: UpdateFunction): Option[Label]
}

case class SLTUpdateProof(key: SLTKey, proofSeq: Seq[SLTProofElement])(implicit hf: CryptographicHash)
  extends SLTModifyingProof {

  def verify(digest: Label, updated: UpdateFunction): Option[Label] = Try {
    val proof: mutable.Queue[SLTProofElement] = mutable.Queue(proofSeq: _*)
    def verifyUpdateRecursive(): (Label, Boolean, Option[Label]) = {
      val nKey = dequeueKey(proof)
      val nValue = dequeueValue(proof)
      val nLevel = dequeueLevel(proof)

      var oldLabel: Label = LabelOfNone
      val (n: FlatNode, found: Boolean) = ByteArray.compare(key, nKey) match {
        case 0 =>
          val nLeft = dequeueLeftLabel(proof)
          val nRight = dequeueRightLabel(proof)
          val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
          oldLabel = n.computeLabel
          n.value = updated(Some(nValue))
          (n, true)
        case i if i < 0 =>
          val nRight = dequeueRightLabel(proof)
          if (proof.isEmpty) {
            val (nLeft, found) = (LabelOfNone, false)
            val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            oldLabel = n.computeLabel
            (n, found)
          } else {
            val (nLeft, found, newLabelLeft) = verifyUpdateRecursive()
            val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            oldLabel = n.computeLabel
            if (found) n.leftLabel = newLabelLeft.get
            (n, found)
          }
        case _ =>
          val nLeft = dequeueLeftLabel(proof)
          if (proof.isEmpty) {
            val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, LabelOfNone, None)
            oldLabel = n.computeLabel
            (n, false)
          } else {
            val (nRight, found, newLabelRight) = verifyUpdateRecursive()
            val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            oldLabel = n.computeLabel
            if (found) n.rightLabel = newLabelRight.get
            (n, found)
          }
      }
      val newLabel = if (found) Some(n.computeLabel) else None
      (oldLabel, found, newLabel)
    }

    val (h, v, n) = verifyUpdateRecursive()
    if (v && (h sameElements digest)) n else None
  }.getOrElse(None)

}

case class SLTInsertProof(key: SLTKey, proofSeq: Seq[SLTProofElement])(implicit hf: CryptographicHash)
  extends SLTModifyingProof {

  def verify(digest: Label, updated: Option[SLTValue] => SLTValue): Option[Label] = Try {
    val proof: mutable.Queue[SLTProofElement] = mutable.Queue(proofSeq: _*)
    val rootKey = dequeueKey(proof)
    val rootValue = dequeueValue(proof)
    val rootLevel = dequeueLevel(proof)
    val rootLeftLabel = dequeueLeftLabel(proof)

    def verifyInsertHelper(): (Label, FlatNode, Boolean) = {
      if (proof.isEmpty) {
        val level = SLTree.computeLevel(key)
        // this coinflip needs to be the same as in the prover’s case --
        // the strategy used for skip lists will work here, too
        val n = new FlatNode(key, updated(None), level, LabelOfNone, LabelOfNone, None)
        (LabelOfNone, n, true)
      } else {
        val rKey = dequeueKey(proof)
        val rValue = dequeueValue(proof)
        val rLevel = dequeueLevel(proof)
        ByteArray.compare(key, rKey) match {
          case 0 =>
            val rLeftLabel = dequeueLeftLabel(proof)
            val rRightLabel = dequeueRightLabel(proof)
            val r = new FlatNode(rKey, rValue, rLevel, rLeftLabel, rRightLabel, None)
            (r.label, r, false)
          case i if i < 0 =>
            val rRightLabel = dequeueRightLabel(proof)
            val (rLeftLabel, newLeft, success) = verifyInsertHelper()
            val r = new FlatNode(rKey, rValue, rLevel, rLeftLabel, rRightLabel, None)
            val oldLabel = r.label
            if (success) {
              // Attach the newLeft if its level is smaller than our level;
              // compute its hash if needed,
              // because it’s not going to move up
              val newR = if (newLeft.level < r.level) {
                r.leftLabel = newLeft.computeLabel
                r
              } else {
                // We need to rotate r with newLeft
                r.leftLabel = newLeft.rightLabel
                newLeft.rightLabel = r.computeLabel
                newLeft
                // don’t compute the label of newR, because it may still change
              }
              (oldLabel, newR, true)
            }
            else (oldLabel, r, false)
          case _ =>
            // x>root.key
            // Everything symmetric, except replace newLeft.level<r.level with
            // newRight.level<= r.level
            // (because on the right level is allowed to be the same as of the child,
            // but on the left the child has to be smaller)
            val rLeftLabel = dequeueLeftLabel(proof)
            val (rRightLabel, newRight, success) = verifyInsertHelper()
            val r = new FlatNode(rKey, rValue, rLevel, rLeftLabel, rRightLabel, None)
            val oldLabel = r.label
            if (success) {
              // Attach the newLeft if its level is smaller than our level;
              // compute its hash if needed,
              // because it’s not going to move up
              val newR = if (newRight.level <= r.level) {
                r.rightLabel = newRight.computeLabel
                r
              } else {
                // We need to rotate r with newLeft
                r.rightLabel = newRight.leftLabel
                newRight.leftLabel = r.computeLabel
                newRight
                // don’t compute the label of newR, because it may still change
              }
              (oldLabel, newR, true)
            }
            else (oldLabel, r, false)
        }
      }
    }
    val (rootRightLabel, newRight, success) = verifyInsertHelper()
    val root = new FlatNode(rootKey, rootValue, rootLevel, rootLeftLabel, rootRightLabel, None)
    if (success && (root.computeLabel sameElements digest)) {
      root.rightLabel = newRight.computeLabel
      // Elevate the level of the sentinel tower to the level of the newly inserted element,
      // if it’s higher
      if (newRight.level > root.level) root.level = newRight.level
      Some(root.label)
    } else {
      None
    }
  }.getOrElse(None)


}