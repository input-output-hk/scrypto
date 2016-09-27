package scorex.crypto.authds.avltree

import scorex.crypto.authds._
import scorex.crypto.hash.{ThreadUnsafeHash, CryptographicHash}
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.Try


case class AVLModifyProof(key: AVLKey, proofSeq: Seq[AVLProofElement])
                         (implicit hf: ThreadUnsafeHash) extends TwoPartyProof[AVLKey, AVLValue] {

  def verify(digest: Label, updateFunction: UpdateFunction, toInsertIfNotFound: Boolean = true): Option[Label] = Try {
    val proof: mutable.Queue[TwoPartyProofElement] = mutable.Queue(proofSeq: _*)

    // returns the new flat root
    // and an indicator whether tree has been modified at r or below
    // Also returns the label of the old root
    def verifyHelper(): (VerifierNodes, Boolean, Boolean, Label) = {
      dequeueDirection(proof) match {
        case LeafFound =>
          val nextLeafKey: AVLKey = dequeueNextLeafKey(proof)
          val value: AVLValue = dequeueValue(proof)
          val oldLeaf = Leaf(key, value, nextLeafKey)
          val newLeaf = Leaf(key, updateFunction(Some(value)), nextLeafKey)
          (newLeaf, true, false, oldLeaf.label)
        case LeafNotFound =>
          val neigbourLeafKey = dequeueKey(proof)
          val nextLeafKey: AVLKey = dequeueNextLeafKey(proof)
          val value: AVLValue = dequeueValue(proof)
          require(ByteArray.compare(neigbourLeafKey, key) < 0)
          require(ByteArray.compare(key, nextLeafKey) < 0)

          val r = new Leaf(neigbourLeafKey, value, nextLeafKey)
          val oldLabel = r.label
          if (toInsertIfNotFound) {
            val newLeaf = new Leaf(key, updateFunction(None), r.nextLeafKey)
            r.nextLeafKey = key
            val newR = VerifierNode(LabelOnlyNode(r.label), LabelOnlyNode(newLeaf.label), 0)
            (newR, true, true, oldLabel)
          } else {
            (r, false, false, oldLabel)
          }
        case GoingLeft =>
          val rightLabel: Label = dequeueRightLabel(proof)
          val balance: Level = dequeueBalance(proof)

          var (newLeftM: VerifierNodes, changeHappened: Boolean, childHeightIncreased: Boolean, oldLeftLabel) = verifyHelper()

          val r = VerifierNode(LabelOnlyNode(oldLeftLabel), LabelOnlyNode(rightLabel), balance)
          val oldLabel = r.label

          // balance = -1 if left higher, +1 if left lower
          if (changeHappened) {
            if (childHeightIncreased && r.balance < 0) {
              // need to rotate
              newLeftM match {
                // at this point we know newleftM must be an internal node an not a leaf -- b/c height increased;  TODO: make this more scala-like
                case newLeft: VerifierNode =>
                  if (newLeft.balance < 0) {
                    // single rotate
                    r.left = newLeft.right
                    r.balance = 0
                    newLeft.right = r
                    newLeft.balance = 0
                    (newLeft, true, false, oldLabel)
                  }

                  else {
                    // double rotate
                    val newRootM = newLeft.right
                    val newRoot = newRootM.asInstanceOf[VerifierNode]

                    r.left = newRoot.right
                    newRoot.right = r
                    newLeft.right = newRoot.left
                    newRoot.left = newLeft
                    newRoot.balance match {
                      case 0 =>
                        // newRoot is a newly created node
                        newLeft.balance = 0
                        r.balance = 0
                      case -1 =>
                        newLeft.balance = 0
                        r.balance = 1
                      case 1 =>
                        newLeft.balance = -1
                        r.balance = 0
                    }
                    newRoot.balance = 0
                    (newRoot, true, false, oldLabel)
                  }

                case newLeft =>
                  require(false) // TODO : make this more scala-like
                  (r, true, false, oldLabel) // TODO: this return value is not needed
              }

            } else {
              // no need to rotate
              r.left = newLeftM
              val myHeightIncreased: Boolean = (childHeightIncreased && r.balance == 0)
              if (childHeightIncreased) r.balance -= 1
              (r, true, myHeightIncreased, oldLabel)
            }

          } else {
            // no change happened
            (r, false, false, oldLabel)
          }

        case GoingRight =>
          val leftLabel: Label = dequeueLeftLabel(proof)
          val balance: Level = dequeueBalance(proof)


          var (newRightM: VerifierNodes, changeHappened: Boolean, childHeightIncreased: Boolean, oldRightLabel) = verifyHelper()

          val r = VerifierNode(LabelOnlyNode(leftLabel), LabelOnlyNode(oldRightLabel), balance)
          val oldLabel = r.label

          if (changeHappened) {
            if (childHeightIncreased && r.balance > 0) {
              // need to rotate
              newRightM match {
                // at this point we know newRightM must be an internal node an not a leaf -- b/c height increased;  TODO: make this more scala-like
                case newRight: VerifierNode =>
                  if (newRight.balance > 0) {
                    // single rotate
                    r.right = newRight.left
                    r.balance = 0
                    newRight.left = r
                    newRight.balance = 0
                    (newRight, true, false, oldLabel)
                  }

                  else {
                    // double rotate
                    val newRootM = newRight.left
                    val newRoot = newRootM.asInstanceOf[VerifierNode]

                    r.right = newRoot.left
                    newRoot.left = r
                    newRight.left = newRoot.right
                    newRoot.right = newRight

                    newRoot.balance match {
                      case 0 =>
                        // newRoot is a newly created node
                        newRight.balance = 0
                        r.balance = 0
                      case -1 =>
                        newRight.balance = 1
                        r.balance = 0
                      case 1 =>
                        newRight.balance = 0
                        r.balance = -1
                    }
                    newRoot.balance = 0

                    (newRoot, true, false, oldLabel)
                  }

                case newRight =>
                  require(false) // TODO : make this more scala-like
                  (r, true, false, oldLabel) // TODO: this return value is not needed
              }
            } else {
              // no need to rotate
              r.right = newRightM
              val myHeightIncreased: Boolean = childHeightIncreased && r.balance == 0
              if (childHeightIncreased) r.balance += 1
              (r, true, myHeightIncreased, oldLabel)
            }
          } else {
            // no change happened
            (r, false, false, oldLabel)
          }
      }
    }

    var (newTopNode: VerifierNodes, changeHappened: Boolean, heighIncreased: Boolean, oldLabel: Label) = verifyHelper()
    if (oldLabel sameElements digest) {
      Some(newTopNode.label)
    } else {
      None
    }
  }.getOrElse(None)

}
