package scorex.crypto.authds.wtree

import scorex.crypto.hash.CryptographicHash
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.Try

sealed trait WTProof {

  def dequeueValue(proof: mutable.Queue[WTProofElement]): WTValue = {
    proof.dequeue().asInstanceOf[WTProofValue].e
  }

  def dequeueKey(proof: mutable.Queue[WTProofElement]): WTKey = {
    proof.dequeue().asInstanceOf[WTProofKey].e
  }

  def dequeueNextLeafKey(proof: mutable.Queue[WTProofElement]): WTKey  = {
    proof.dequeue().asInstanceOf[WTProofNextLeafKey].e
  }

  def dequeueRightLabel(proof: mutable.Queue[WTProofElement]): Label = {
    proof.dequeue().asInstanceOf[WTProofRightLabel].e
  }

  def dequeueLeftLabel(proof: mutable.Queue[WTProofElement]): Label = {
    proof.dequeue().asInstanceOf[WTProofLeftLabel].e
  }

  def dequeueDirection(proof: mutable.Queue[WTProofElement]): Direction = {
    proof.dequeue().asInstanceOf[WTProofDirection].direction
  }

  def dequeueLevel(proof: mutable.Queue[WTProofElement]): Level = {
    proof.dequeue().asInstanceOf[WTProofLevel].e
  }
}


case class WTModifyProof(x: WTKey, proofSeq: Seq[WTProofElement])(implicit hf: CryptographicHash)
  extends WTProof {

  def verify(digest: Label, updated: UpdateFunction, toInsertIfNotFound: Boolean = true): Option[Label] = Try {
    val proof: mutable.Queue[WTProofElement] = mutable.Queue(proofSeq: _*)

    // returns the new flat root, an indicator whether tree has been modified at r or below,
    // and an indicator whether the new root already has its label correctly computed
    // Also returns the label of the old root
    def verifyHelper(): (VerifierNodes, Boolean, Boolean, Label) = {
      dequeueDirection(proof) match {
        case LeafFound =>
          val nextLeafKey: WTKey = dequeueNextLeafKey(proof)
          val value: WTValue = dequeueValue(proof)
          val oldLeaf = Leaf(x, value, nextLeafKey)
          val oldLabel = oldLeaf.computeLabel
          val newLeaf = Leaf(x, updated(Some(value)), nextLeafKey)
          (newLeaf, true, true, oldLabel)
        case LeafNotFound =>
          val key = dequeueKey(proof)
          val nextLeafKey: WTKey = dequeueNextLeafKey(proof)
          val value: WTValue = dequeueValue(proof)
          require(ByteArray.compare(key, x) < 0)
          require(ByteArray.compare(x, nextLeafKey) < 0)

          val r = new Leaf(x, value, nextLeafKey)
          val oldLabel = r.label
          if (toInsertIfNotFound) {
            val newLeaf = new Leaf(x, updated(None), r.nextLeafKey)
            r.nextLeafKey = x
            r.label = r.computeLabel
            val level = levelFromKey(key)
            //TODO check VerifierNode(r.label, newLeaf.label, level) or VerifierNode(newLeaf.label, r.label, level)?
            val newR = VerifierNode(r.label, newLeaf.label, level)
            (newR, true, false, oldLabel)
          } else {
            (r, false, true, oldLabel)
          }
        case GoingLeft =>
          val rightLabel: Label = dequeueRightLabel(proof)
          val level: Level = dequeueLevel(proof)

          var (newLeftM: VerifierNodes, changeHappened: Boolean, rootLabelComputed: Boolean, oldLeftLabel) = verifyHelper()

          val r = VerifierNode(oldLeftLabel, rightLabel, level)
          val oldLabel = r.label

          if (changeHappened) {
            // Attach the newLeft if its level is smaller than our level;
            // compute its hash if needed,
            // because it is not going to move up
            val newR = newLeftM match {
              case newLeft: VerifierNode if newLeft.level >= r.level =>
                // We need to rotate r with newLeft
                r.leftLabel = newLeft.rightLabel
                r.label = r.computeLabel
                newLeft.rightLabel = r.label
                rootLabelComputed = false
                newLeft
              // do not compute the label of newR, because it may still change
              case newLeft =>
                if (!rootLabelComputed) {
                  newLeft.label = newLeft.computeLabel
                  rootLabelComputed = true
                }
                r.leftLabel = newLeft.label
                r
            }
            (newR, true, rootLabelComputed, oldLabel)
          } else {
            (r, false, true, oldLabel)
          }
        case GoingRight =>
          val leftLabel: Label = dequeueLeftLabel(proof)
          val level: Level = dequeueLevel(proof)

          var (newRightM: VerifierNodes, changeHappened: Boolean, rootLabelComputed: Boolean, oldRightLabel) = verifyHelper()

          val r = VerifierNode(leftLabel, oldRightLabel, level)
          r.label = r.computeLabel
          val oldLabel = r.label

          if (changeHappened) {
            // Attach the newRight if its level is smaller than or equal to our level;
            // compute its hash if needed,
            // because it is not going to move up
            // This is symmetric to the left case, except of < replaced with <= on the next
            // line
            val newR = newRightM match {
              case newRight: VerifierNode if newRight.level < r.level =>
                // We need to rotate r with newRight
                r.rightLabel = newRight.leftLabel
                r.label = r.computeLabel
                newRight.leftLabel = r.label
                rootLabelComputed = false
                newRight
              // do not compute the label of newR, because it may still change
              case newRight =>
                if (!rootLabelComputed) {
                  newRight.label = newRight.computeLabel
                  rootLabelComputed = true
                }
                r.rightLabel = newRight.label
                r.label = r.computeLabel
                r
            }
            (newR, true, rootLabelComputed, oldLabel)
          } else {
            // no change happened
            (r, false, true, oldLabel)
          }
      }
    }

    var (newTopNode: VerifierNodes, changeHappened: Boolean, rootLabelComputed: Boolean, oldLabel: Label) = verifyHelper()
    if (oldLabel sameElements digest) {
      if (!rootLabelComputed) newTopNode.label = newTopNode.computeLabel
      Some(newTopNode.label)
    } else {
      None
    }
  }.get
//  }.getOrElse(None)

}
