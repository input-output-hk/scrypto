package scorex.crypto.authds.binary

import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.Try

sealed trait SLTProof {
  def isValid(digest: Label): Boolean
}

case class SLTLookupProof(x: SLTKey, proof: mutable.Queue[SLTProofElement]) extends SLTProof {


  override def isValid(digest: Label): Boolean = verifyLookup(digest)._1

  def verifyLookup(digest: Label): (Boolean, Option[SLTValue]) = {
    val (h, v) = verifyLookupRecursive()
    if (h sameElements digest) (true, v) else (false, None)
  }

  def verifyLookupRecursive(): (Label, Option[SLTValue]) = {
    val nKey = proof.dequeue().asInstanceOf[SLTProofKey].e
    val nValue = proof.dequeue().asInstanceOf[SLTProofValue].e
    val nLevel = proof.dequeue().asInstanceOf[SLTProofLevel].e
    ByteArray.compare(x, nKey) match {
      case 0 =>
        val nLeft = proof.dequeue().asInstanceOf[SLTProofLeftLabel].e
        val nRight = proof.dequeue().asInstanceOf[SLTProofRightLabel].e
        val n = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
        (n.label, Some(n.value))
      case o if o < 0 =>
        val nRight = proof.dequeue().asInstanceOf[SLTProofRightLabel].e
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
        val nLeft = proof.dequeue().asInstanceOf[SLTProofLeftLabel].e
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
}

case class SLTUpdateProof(x: SLTKey, newVal: SLTValue, proof: mutable.Queue[SLTProofElement]) extends SLTProof {

  override def isValid(digest: Label): Boolean = verifyUpdate(digest)._1

  def verifyUpdate(digest: Label): (Boolean, Option[Boolean], Option[Label]) = {
    val (h, v, n) = verifyUpdateRecursive()
    if (h sameElements digest) (true, v, n) else (false, None, None)
  }

  def verifyUpdateRecursive(): (Label, Option[Boolean], Option[Label]) = ???

  /*
    def verifyUpdateRecursive(node: FlatNode): (Label, Option[Boolean], Option[Label]) = {
      val nKey = proof.dequeue().asInstanceOf[SLTProofKey].e
      val nValue = proof.dequeue().asInstanceOf[SLTProofValue].e
      val nLevel = proof.dequeue().asInstanceOf[SLTProofLevel].e

      var found = false
      ByteArray.compare(x, nKey) match {
        case 0 =>
          val nLeft = proof.dequeue().asInstanceOf[SLTProofLeftLabel].e
          val nRight = proof.dequeue().asInstanceOf[SLTProofRightLabel].e
          val n: FlatNode = new FlatNode(nKey, nValue, nLevel, nLeft, nRight, None)
          n.label = n.computeLabel
          n.value = newVal
          found = true
        case i if i < 0 =>
          ???
        case _ =>
          ???
      }
      ???
    }
  */
}

case class SLTInsertProof(key: SLTKey, value: SLTValue, proof: mutable.Queue[SLTProofElement]) extends SLTProof {

  override def isValid(digest: Label): Boolean = verifyInsert(digest)._1

  def verifyInsert(digest: Label): (Boolean, Option[Boolean], Option[Label]) = Try {

    val rootKey = proof.dequeue().asInstanceOf[SLTProofKey].e
    val rootValue = proof.dequeue().asInstanceOf[SLTProofValue].e
    val rootLevel = proof.dequeue().asInstanceOf[SLTProofLevel].e
    val rootLeftLabel = proof.dequeue().asInstanceOf[SLTProofLeftLabel].e
    val (rootRightLabel, newRight, success) = verifyInsertHelper(key, value)
    val root = new FlatNode(rootKey, rootValue, rootLevel, rootLeftLabel, rootRightLabel, None)
    if (!(root.label sameElements digest)) {
      (false, None, None)
    } else {
      if (success) {
        if (newRight.label sameElements LabelOfNone) {
          root.rightLabel = newRight.computeLabel
        }
        // Elevate the level of the sentinel tower to the level of the newly inserted element,
        // if it’s higher
        if (newRight.level > root.level) root.level = newRight.level
        root.label = root.computeLabel
      }
      (true, Some(success), Some(root.label))
    }
  }.getOrElse((false, None, None))

  private def verifyInsertHelper(x: SLTKey, value: SLTValue): (Label, FlatNode, Boolean) = {
    if (proof.isEmpty) {
      val level = SLTree.computeLevel(x, value)
      // this coinflip needs to be the same as in the prover’s case --
      // the strategy used for skip lists will work here, too
      val n = new FlatNode(x, value, level, LabelOfNone, LabelOfNone, None)
      (LabelOfNone, n, true)
    } else {
      val rKey = proof.dequeue().asInstanceOf[SLTProofKey].e
      val rValue = proof.dequeue().asInstanceOf[SLTProofValue].e
      val rLevel = proof.dequeue().asInstanceOf[SLTProofLevel].e
      ByteArray.compare(x, rKey) match {
        case 0 =>
          val rLeftLabel = proof.dequeue().asInstanceOf[SLTProofLeftLabel].e
          val rRightLabel = proof.dequeue().asInstanceOf[SLTProofRightLabel].e
          val r = new FlatNode(rKey, rValue, rLevel, rLeftLabel, rRightLabel, None)
          (r.label, r, false)
        case i if i < 0 =>
          val rRightLabel = proof.dequeue().asInstanceOf[SLTProofRightLabel].e
          val (rLeftLabel, newLeft, success) = verifyInsertHelper(x, value)
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
          val rRightLabel = proof.dequeue().asInstanceOf[SLTProofRightLabel].e
          val (rLeftLabel, newRight, success) = verifyInsertHelper(x, value)
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


}