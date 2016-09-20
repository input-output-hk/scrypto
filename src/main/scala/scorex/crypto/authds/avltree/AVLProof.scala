package scorex.crypto.authds.avltree

import scorex.crypto.hash.CryptographicHash
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.Try

sealed trait AVLProof {

  def dequeueValue(proof: mutable.Queue[AVLProofElement]): WTValue = {
    proof.dequeue().asInstanceOf[AVLProofValue].e
  }

  def dequeueKey(proof: mutable.Queue[AVLProofElement]): WTKey = {
    proof.dequeue().asInstanceOf[AVLProofKey].e
  }

  def dequeueNextLeafKey(proof: mutable.Queue[AVLProofElement]): WTKey = {
    proof.dequeue().asInstanceOf[AVLProofNextLeafKey].e
  }

  def dequeueRightLabel(proof: mutable.Queue[AVLProofElement]): Label = {
    proof.dequeue().asInstanceOf[AVLProofRightLabel].e
  }

  def dequeueLeftLabel(proof: mutable.Queue[AVLProofElement]): Label = {
    proof.dequeue().asInstanceOf[AVLProofLeftLabel].e
  }

  def dequeueDirection(proof: mutable.Queue[AVLProofElement]): Direction = {
    proof.dequeue().asInstanceOf[AVLProofDirection].direction
  }

  def dequeueLevel(proof: mutable.Queue[AVLProofElement]): Level = {
    proof.dequeue().asInstanceOf[AVLProofLevel].e
  }
}


case class AVLModifyProof(key: WTKey, proofSeq: Seq[AVLProofElement])
                         (implicit hf: CryptographicHash, levelFunc: LevelFunction) extends AVLProof {

  def verify(digest: Label, updateFunction: UpdateFunction, toInsertIfNotFound: Boolean = true): Option[Label] = Try {
    val proof: mutable.Queue[AVLProofElement] = mutable.Queue(proofSeq: _*)

    // returns the new flat root
    // and an indicator whether tree has been modified at r or below
    // Also returns the label of the old root
    def verifyHelper(): (VerifierNodes, Boolean, Label) = {
      dequeueDirection(proof) match {
        case LeafFound =>
          val nextLeafKey: WTKey = dequeueNextLeafKey(proof)
          val value: WTValue = dequeueValue(proof)
          val oldLeaf = Leaf(key, value, nextLeafKey)
          val newLeaf = Leaf(key, updateFunction(Some(value)), nextLeafKey)
          (newLeaf, true, oldLeaf.label)
        case LeafNotFound =>
          val neigbourLeafKey = dequeueKey(proof)
          val nextLeafKey: WTKey = dequeueNextLeafKey(proof)
          val value: WTValue = dequeueValue(proof)
          require(ByteArray.compare(neigbourLeafKey, key) < 0)
          require(ByteArray.compare(key, nextLeafKey) < 0)

          val r = new Leaf(neigbourLeafKey, value, nextLeafKey)
          val oldLabel = r.label
          if (toInsertIfNotFound) {
            val newLeaf = new Leaf(key, updateFunction(None), r.nextLeafKey)
            r.nextLeafKey = key
            val level = levelFunc(key)
            val newR = VerifierNode(r.label, newLeaf.label, level)
            (newR, true, oldLabel)
          } else {
            (r, false, oldLabel)
          }
        case GoingLeft =>
          val rightLabel: Label = dequeueRightLabel(proof)
          val level: Level = dequeueLevel(proof)

          var (newLeftM: VerifierNodes, changeHappened: Boolean, oldLeftLabel) = verifyHelper()

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

          var (newRightM: VerifierNodes, changeHappened: Boolean, oldRightLabel) = verifyHelper()

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

    var (newTopNode: VerifierNodes, changeHappened: Boolean, oldLabel: Label) = verifyHelper()
    if (oldLabel sameElements digest) {
      Some(newTopNode.label)
    } else {
      None
    }
  }.getOrElse(None)

}
