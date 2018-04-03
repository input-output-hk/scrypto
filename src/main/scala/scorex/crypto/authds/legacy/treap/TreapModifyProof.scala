package scorex.crypto.authds.legacy.treap

import scorex.crypto.authds._
import scorex.crypto.authds.avltree.batch.Modification
import scorex.crypto.authds.legacy.treap.Constants.LevelFunction
import scorex.crypto.hash._
import scorex.utils.ByteArray

import scala.util.{Failure, Success, Try}

case class TreapModifyProof(key: ADKey, proofSeq: Seq[WTProofElement])
                           (implicit hf: CryptographicHash[_ <: Digest], levelFunc: LevelFunction)
  extends TwoPartyProof {

  def verify(digest: ADDigest, updateFn: Modification#UpdateFunction): Option[ADDigest] = Try {
    initializeIterator()

    // returns the new flat root
    // and an indicator whether tree has been modified at r or below
    // Also returns the label of the old root
    def verifyHelper(): (VerifierNodes, Boolean, Digest) = {
      dequeueDirection() match {
        case LeafFound =>
          val nextLeafKey: ADKey = dequeueNextLeafKey()
          val value: ADValue = dequeueValue()
          updateFn(Some(value)) match {
            case Success(None) => //delete value
              ???
            case Success(Some(v)) => //update value
              val oldLeaf = Leaf(key, value, nextLeafKey)
              val newLeaf = Leaf(key, v, nextLeafKey)
              (newLeaf, true, oldLeaf.label)
            case Failure(e) => // found incorrect value
              throw e
          }
        case LeafNotFound =>
          val neighbourLeafKey = dequeueKey()
          val nextLeafKey: ADKey = dequeueNextLeafKey()
          val value: ADValue = dequeueValue()
          require(ByteArray.compare(neighbourLeafKey, key) < 0)
          require(ByteArray.compare(key, nextLeafKey) < 0)

          val r = Leaf(neighbourLeafKey, value, nextLeafKey)
          val oldLabel = r.label
          updateFn(None) match {
            case Success(None) => //don't change anything, just lookup
              ???
            case Success(Some(v)) => //insert new value
              val newLeaf = Leaf(key, v, r.nextLeafKey)
              r.nextLeafKey = key
              val level = levelFunc(key)
              val newR = VerifierNode(r.label, newLeaf.label, level)
              (newR, true, oldLabel)
            case Failure(e) => // found incorrect value
              // (r, false, false, oldLabel)
              throw e
          }
        case GoingLeft =>
          val rightLabel: Digest = dequeueRightLabel()
          val level: Level = dequeueLevel()

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
          val leftLabel: Digest = dequeueLeftLabel()
          val level: Level = dequeueLevel()

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
      Some(ADDigest @@ newTopNode.label)
    } else {
      None
    }
  }.getOrElse(None)

}
