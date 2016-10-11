package scorex.crypto.authds.treap

import scorex.crypto.authds._
import scorex.crypto.hash.ThreadUnsafeHash
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.{Success, Try}

case class TreapModifyProof(key: TreapKey, proofSeq: Seq[WTProofElement])
                           (implicit hf: ThreadUnsafeHash, levelFunc: LevelFunction)
  extends TwoPartyProof[TreapKey, TreapValue] {

  def verify(digest: Label, updateFunction: UpdateFunction): Option[Label] = Try {
    val proof: mutable.Queue[TwoPartyProofElement] = mutable.Queue(proofSeq: _*)

    // returns the new flat root
    // and an indicator whether tree has been modified at r or below
    // Also returns the label of the old root
    def verifyHelper(): (VerifierNodes, Boolean, Label) = {
      dequeueDirection(proof) match {
        case LeafFound =>
          val nextLeafKey: TreapKey = dequeueNextLeafKey(proof)
          val value: TreapValue = dequeueValue(proof)
          val oldLeaf = Leaf(key, value, nextLeafKey)
          val newLeaf = Leaf(key, updateFunction(Some(value)).get, nextLeafKey)
          (newLeaf, true, oldLeaf.label)
        case LeafNotFound =>
          val neighbourLeafKey = dequeueKey(proof)
          val nextLeafKey: TreapKey = dequeueNextLeafKey(proof)
          val value: TreapValue = dequeueValue(proof)
          require(ByteArray.compare(neighbourLeafKey, key) < 0)
          require(ByteArray.compare(key, nextLeafKey) < 0)

          val r = new Leaf(neighbourLeafKey, value, nextLeafKey)
          val oldLabel = r.label
          updateFunction(None) match {
            case Success(v) =>
              val newLeaf = new Leaf(key, v, r.nextLeafKey)
              r.nextLeafKey = key
              val level = levelFunc(key)
              val newR = VerifierNode(r.label, newLeaf.label, level)
              (newR, true, oldLabel)
            case _ =>
              (r, false, oldLabel)
          }
        case GoingLeft =>
          val rightLabel: Label = dequeueRightLabel(proof)
          val level: Level = dequeueLevel(proof)

          val (newLeftM, changeHappened, oldLeftLabel) = verifyHelper()

          val r = VerifierNode(oldLeftLabel, rightLabel, level)
          val oldLabel = r.label

          if (changeHappened) {
            newLeftM match {
              case newLeft: VerifierNode if newLeft.level >= r.level =>
                // We need to rotate r with newLeft
                r.leftLabel = newLeft.rightLabel
                newLeft.rightLabel = r.label
                (newLeft, true, oldLabel)
              case newLeft =>
                // Attach the newLeft because its level is smaller than our level
                r.leftLabel = newLeft.label
                (r, true, oldLabel)
            }
          } else {
            (r, false, oldLabel)
          }
        case GoingRight =>
          val leftLabel: Label = dequeueLeftLabel(proof)
          val level: Level = dequeueLevel(proof)

          val (newRightM, changeHappened, oldRightLabel) = verifyHelper()

          val r = VerifierNode(leftLabel, oldRightLabel, level)
          val oldLabel = r.label

          if (changeHappened) {
            // This is symmetric to the left case, except of >= replaced with > in the
            // level comparison
            newRightM match {
              case newRight: VerifierNode if newRight.level > r.level =>
                // We need to rotate r with newRight
                r.rightLabel = newRight.leftLabel
                newRight.leftLabel = r.label
                (newRight, true, oldLabel)
              case newRight =>
                // Attach the newRight because its level is smaller than or equal to our level
                r.rightLabel = newRight.label
                (r, true, oldLabel)
            }
          } else {
            // no change happened
            (r, false, oldLabel)
          }
      }
    }

    val (newTopNode, changeHappened, oldLabel) = verifyHelper()
    if (oldLabel sameElements digest) {
      Some(newTopNode.label)
    } else {
      None
    }
  }.getOrElse(None)

}
