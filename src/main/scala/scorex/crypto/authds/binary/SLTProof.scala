package scorex.crypto.authds.binary

import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.Try

sealed trait SLTProof {
  def isValid(digest: Label): Boolean

  def dequeueValue(proof: mutable.Queue[SLTProofElement]): SLTValue = {
    proof.dequeue().asInstanceOf[SLTProofValue].e
  }

  def dequeueKey(proof: mutable.Queue[SLTProofElement]): SLTKey = {
    proof.dequeue().asInstanceOf[SLTProofKey].e
  }

  def dequeueRightLabel(proof: mutable.Queue[SLTProofElement]): Label = {
    proof.dequeue().asInstanceOf[SLTProofRightLabel].e
  }

  def dequeueLeftLabel(proof: mutable.Queue[SLTProofElement]): Label = {
    proof.dequeue().asInstanceOf[SLTProofLeftLabel].e
  }

  def dequeueLevel(proof: mutable.Queue[SLTProofElement]): Int = {
    proof.dequeue().asInstanceOf[SLTProofLevel].e
  }
}

case class SLTLookupProof(x: SLTKey, proofSeq: Seq[SLTProofElement]) extends SLTProof {


  override def isValid(digest: Label): Boolean = verifyLookup(digest).map(_._1).getOrElse(false)

  def verifyLookup(digest: Label): Try[(Boolean, Option[SLTValue])] = Try {
    val proof: mutable.Queue[SLTProofElement] = mutable.Queue(proofSeq: _*)
    def verifyLookupRecursive(): (Label, Option[SLTValue]) = {
      val nKey = dequeueKey(proof)
      val nValue = dequeueValue(proof)
      val nLevel = dequeueLevel(proof)
      ByteArray.compare(x, nKey) match {
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
    if (h sameElements digest) (true, v) else (false, None)
  }

}

case class SLTUpdateProof(x: SLTKey, newVal: SLTValue, proofSeq: Seq[SLTProofElement]) extends SLTProof {
  override def isValid(digest: Label): Boolean = verifyUpdate(digest).map(_._1).getOrElse(false)

  def verifyUpdate(digest: Label): Try[(Boolean, Boolean, Option[Label])] = Try {
    val proof: mutable.Queue[SLTProofElement] = mutable.Queue(proofSeq: _*)
    def verifyUpdateRecursive(): (Label, Boolean, Option[Label]) = {
      val nKey = dequeueKey(proof)
      val nValue = dequeueValue(proof)
      val nLevel = dequeueLevel(proof)

      val (n: FlatNode, found: Boolean) = ByteArray.compare(x, nKey) match {
        case 0 =>
          val nLeft = dequeueLeftLabel(proof)
          val nRight = dequeueRightLabel(proof)
          val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
          n.label = n.computeLabel
          n.value = newVal
          (n, true)
        case i if i < 0 =>
          val nRight = dequeueRightLabel(proof)
          if (proof.isEmpty) {
            val (nLeft, found) = (LabelOfNone, false)
            val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            n.label = n.computeLabel
            (n, found)
          } else {
            val (nLeft, found, newLabelLeft) = verifyUpdateRecursive()
            val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            n.label = n.computeLabel
            if (found) n.leftLabel = newLabelLeft.get
            (n, found)
          }
        case _ =>
          val nLeft = dequeueLeftLabel(proof)
          if (proof.isEmpty) {
            val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, LabelOfNone, None)
            n.label = n.computeLabel
            (n, false)
          } else {
            val (nRight, found, newLabelRight) = verifyUpdateRecursive()
            val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
            if (found) n.rightLabel = newLabelRight.get
            (n, found)
          }
      }
      val newLabel = if (found) Some(n.computeLabel) else None
      (n.label, found, newLabel)
    }

    val (h, v, n) = verifyUpdateRecursive()
    if (h sameElements digest) (true, v, n) else (false, false, None)
  }

}

case class SLTInsertProof(key: SLTKey, value: SLTValue, proofSeq: Seq[SLTProofElement]) extends SLTProof {

  override def isValid(digest: Label): Boolean = verifyInsert(digest).map(_._1).getOrElse(false)

  def verifyInsert(digest: Label): Try[(Boolean, Boolean, Option[Label])] = Try {
    val proof: mutable.Queue[SLTProofElement] = mutable.Queue(proofSeq: _*)
    val rootKey = dequeueKey(proof)
    val rootValue = dequeueValue(proof)
    val rootLevel = dequeueLevel(proof)
    val rootLeftLabel = dequeueLeftLabel(proof)

    def verifyInsertHelper(): (Label, FlatNode, Boolean) = {
      if (proof.isEmpty) {
        val level = SLTree.computeLevel(key, value)
        // this coinflip needs to be the same as in the prover’s case --
        // the strategy used for skip lists will work here, too
        val n = new FlatNode(key, value, level, LabelOfNone, LabelOfNone, None)
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
                if (newLeft.label sameElements LabelOfNone) {
                  newLeft.label = newLeft.computeLabel
                }
                r.leftLabel = newLeft.label
                r.label = r.computeLabel
                r
              } else {
                // We need to rotate r with newLeft
                r.leftLabel = newLeft.rightLabel
                r.label = r.computeLabel
                newLeft.rightLabel = r.label
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
                if (newRight.label sameElements LabelOfNone) {
                  newRight.label = newRight.computeLabel
                }
                r.rightLabel = newRight.label
                r.label = r.computeLabel
                r
              } else {
                // We need to rotate r with newLeft
                r.rightLabel = newRight.leftLabel
                r.label = r.computeLabel
                newRight.leftLabel = r.label
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
    if (!(root.label sameElements digest)) {
      (false, false, None)
    } else {
      if (success) {
        root.rightLabel = newRight.computeLabel
        // Elevate the level of the sentinel tower to the level of the newly inserted element,
        // if it’s higher
        if (newRight.level > root.level) root.level = newRight.level
        root.label = root.computeLabel
      }
      (true, success, Some(root.label))
    }
  }


}