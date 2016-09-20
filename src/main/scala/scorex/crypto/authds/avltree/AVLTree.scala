package scorex.crypto.authds.avltree

import scorex.crypto.hash.{Blake2b256, CryptographicHash}
import scorex.utils.ByteArray

// WE NEED TO CREATE A NEW TYPE OF INFORMATION IN THE PROOF: `ProofDirection, which can be leafFound, leafNotFound, goingLeft, or goingRight
// It is needed to give hints to the verifier whether which way to go

class AVLTree[HF <: CryptographicHash](rootOpt: Option[Leaf] = None)
                                      (implicit hf: HF = Blake2b256, lf: LevelFunction = Level.skiplistLevel) {

  var topNode: ProverNodes = rootOpt.getOrElse (Leaf(NegativeInfinity._1, NegativeInfinity._2, PositiveInfinity._1))

  def rootHash(): Label = topNode.label

  // We could add return values here:
  // - we could return boolean indicating whether x was found
  // - we could val or newVal
  // - more generally, we could return the result of updateFunction (which could have its own return type,
  // for example returning both old value and new value, or some sort of success/failure)
  // I am not sure what's needed in the application
  //TODO insert toInsertIfNotFound to function
  def modify(key: WTKey, updateFunction: UpdateFunction, toInsertIfNotFound: Boolean = true): AVLModifyProof = {
    require(ByteArray.compare(key, NegativeInfinity._1) > 0)
    require(ByteArray.compare(key, PositiveInfinity._1) < 0)

    val proofStream = new scala.collection.mutable.Queue[AVLProofElement]

    // found tells us if x has been already found above r in the tree
    // returns the new root
    // and an indicator whether tree has been modified at r or below
    def modifyHelper(rNode: ProverNodes, foundAbove: Boolean): (ProverNodes, Boolean) = {
      rNode match {
        case r: Leaf =>
          if (foundAbove) {
            // we already know it's in the tree, so it must be at the current leaf
            proofStream.enqueue(AVLProofDirection(LeafFound))
            proofStream.enqueue(AVLProofNextLeafKey(r.nextLeafKey))
            proofStream.enqueue(AVLProofValue(r.value))
            r.value = updateFunction(Some(r.value))
            (r, true)
          } else {
            // x > r.key
            proofStream.enqueue(AVLProofDirection(LeafNotFound))
            proofStream.enqueue(AVLProofKey(r.key))
            proofStream.enqueue(AVLProofNextLeafKey(r.nextLeafKey))
            proofStream.enqueue(AVLProofValue(r.value))
            if (toInsertIfNotFound) {
              val newLeaf = new Leaf(key, updateFunction(None), r.nextLeafKey)
              r.nextLeafKey = key
              (ProverNode(key, r, newLeaf), true)
            } else {
              (r, false)
            }
          }
        case r: ProverNode =>
          // First figure out the direction in which we need to go
          val (nextStepIsLeft, found) = if (foundAbove) {
            // if it's already been found above, you always go left until leaf
            (true, true)
          } else {
            ByteArray.compare(key, r.key) match {
              case 0 => // found in the tree -- go one step right, then left to the leaf
                (false, true)
              case o if o < 0 => // going left
                (true, false)
              case _ => // going right
                (false, false)
            }
          }
          // Now go recursively in the direction we just figured out
          // Get a new node
          // See if the new node needs to be swapped with r because its level > r.level (if it's left)
          // or its level >= r.level (if it's right)
          if (nextStepIsLeft) {
            proofStream.enqueue(AVLProofDirection(GoingLeft))
            proofStream.enqueue(AVLProofRightLabel(r.rightLabel))
            proofStream.enqueue(AVLProofLevel(r.level))

            var (newLeftM: ProverNodes, changeHappened: Boolean) = modifyHelper(r.left, found)

            if (changeHappened) {
              newLeftM match {
                case newLeft: ProverNode if newLeft.level >= r.level =>
                  // We need to rotate r with newLeft
                  r.left = newLeft.right
                  newLeft.right = r
                  (newLeft, true)
                case newLeft =>
                  // Attach the newLeft because its level is smaller than our level
                  r.left = newLeft
                  (r, true)
              }
            } else {
              // no change happened
              (r, false)
            }
          } else {
            // next step is to the right
            proofStream.enqueue(AVLProofDirection(GoingRight))
            proofStream.enqueue(AVLProofLeftLabel(r.leftLabel))
            proofStream.enqueue(AVLProofLevel(r.level))

            var (newRightM: ProverNodes, changeHappened: Boolean) = modifyHelper(r.right, found)

            if (changeHappened) {
              // This is symmetric to the left case, except of >= replaced with > in the
              // level comparison
              newRightM match {
                case newRight: ProverNode if newRight.level > r.level =>
                  // We need to rotate r with newRight
                  r.right = newRight.left
                  newRight.left = r
                  (newRight, true)
                case newRight =>
                  // Attach the newRight because its level is smaller than or equal to our level
                  r.right = newRight
                  (r, true)
              }
            } else {
              // no change happened
              (r, false)
            }
          }
      }

    }

    var (newTopNode: ProverNodes, changeHappened: Boolean) = modifyHelper(topNode, foundAbove = false)
    topNode = newTopNode
    AVLModifyProof(key, proofStream)
  }

}
