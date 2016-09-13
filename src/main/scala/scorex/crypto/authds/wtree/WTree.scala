package scorex.crypto.authds.wtree

import scorex.crypto.hash.{Blake2b256, CryptographicHash}
import scorex.utils.ByteArray

// WE NEED TO CREATE A NEW TYPE OF INFORMATION IN THE PROOF: `ProofDirection, which can be leafFound, leafNotFound, goingLeft, or goingRight
// It is needed to give hints to the verifier whether which way to go

class WTree[HF <: CryptographicHash](rootOpt: Option[Leaf] = None)(implicit hf: HF = Blake2b256) {

  var topNode: ProverNodes = rootOpt.getOrElse {
    val r = Leaf(NegativeInfinity._1, NegativeInfinity._2, PositiveInfinity._1)
    r.label = r.computeLabel
    r
  }

  def rootHash(): Label = topNode.label

  // We could add return values here:
  // - we could return boolean indicating whether x was found
  // - we could val or newVal
  // - more generally, we could return the result of updateFunction (which could have its own return type,
  // for example returning both old value and new value, or some sort of success/failure)
  // I am not sure what's needed in the application
  def modify(x: WTKey, toInsertIfNotFound: Boolean, updateFunction: UpdateFunction): WTModifyProof = {

    val proofStream = new scala.collection.mutable.Queue[WTProofElement]

    // found tells us if x has been already found above r in the tree
    // returns the new root, an indicator whether tree has been modified at r or below,
    // and an indicator whether the new root already has its label correctly computed
    // (all the nodes below the new root are guaranteed to have the correct label computed)
    def modifyHelper(rNode: ProverNodes, foundIn: Boolean): (ProverNodes, Boolean, Boolean) = {
      var found = foundIn
      rNode match {
        case r: Leaf =>
          if (found) {
            // we already know it's in the tree, so it must be at the current leaf
            proofStream.enqueue(WTProofDirection(LeafFound))
            proofStream.enqueue(WTProofKey(r.nextLeafKey))
            proofStream.enqueue(WTProofValue(r.value))
            r.value = updateFunction(Some(r.value))
            r.label = r.computeLabel
            (r, true, true)
          } else {
            // x > r.key
            proofStream.enqueue(WTProofDirection(LeafNotFound))
            proofStream.enqueue(WTProofKey(r.key))
            proofStream.enqueue(WTProofKey(r.nextLeafKey))
            proofStream.enqueue(WTProofValue(r.value))
            if (toInsertIfNotFound) {
              val newLeaf = new Leaf(x, updateFunction(None), r.nextLeafKey)
              newLeaf.label = newLeaf.computeLabel
              r.nextLeafKey = x
              r.label = r.computeLabel
              // Create a new node without computing its hash, because its hash will change
              (ProverNode(x, r, newLeaf), true, false)
            } else {
              (r, false, true)
            }
          }
        case r: ProverNode =>
          // First figure out the direction in which we need to go
          val nextStepIsLeft =
            if (found) {
              // if it's already been found above, you always go left until leaf
              true
            } else {
              ByteArray.compare(x, r.key) match {
                case 0 => // found in the tree -- go one step right, then left to the leaf
                  found = true
                  false
                case o if o < 0 => // going left
                  true
                case _ => // going right
                  false
              }
            }

          // Now go recursively in the direction we just figured out
          // Get a new node
          // See if the new node needs to be swapped with r because its level > r.level (if it's left)
          // or its level >= r.level (if it's right)

          if (nextStepIsLeft) {
            proofStream.enqueue(WTProofDirection(GoingLeft))
            proofStream.enqueue(WTProofRightLabel(r.rightLabel))
            proofStream.enqueue(WTProofLevel(r.level))

            var (newLeftM: ProverNodes, changeHappened: Boolean, rootLabelComputed: Boolean) = modifyHelper(r.left, found)

            if (changeHappened) {
              // Attach the newLeft if its level is smaller than our level;
              // compute its hash if needed,
              // because it is not going to move up
              val newR = newLeftM match {
                case newLeft: ProverNode if newLeft.level >= r.level =>
                  // We need to rotate r with newLeft
                  r.left = newLeft.right
                  r.label = r.computeLabel
                  newLeft.right = r
                  rootLabelComputed = false
                  newLeft
                case newLeft =>
                  if (!rootLabelComputed) {
                    newLeftM.label = newLeftM.computeLabel
                    rootLabelComputed = true
                  }
                  r.left = newLeftM
                  r.label = r.computeLabel
                  r
              }
              (newR, true, rootLabelComputed)
            } else {
              // no change happened
              (r, false, true)
            }
          }

          else {
            // next step is to the right
            proofStream.enqueue(WTProofDirection(GoingRight))
            proofStream.enqueue(WTProofLeftLabel(r.leftLabel))
            proofStream.enqueue(WTProofLevel(r.level))

            var (newRightM: ProverNodes, changeHappened: Boolean, rootLabelComputed: Boolean) = modifyHelper(r.right, found)

            if (changeHappened) {
              // Attach the newRight if its level is smaller than or equal to our level;
              // compute its hash if needed,
              // because it is not going to move up
              // This is symmetric to the left case, except of < replaced with <=
              // on the next line
              val newR = newRightM match {
                case newRight: ProverNode if newRight.level < r.level =>
                  // We need to rotate r with newRight
                  r.right = newRight.left
                  r.label = r.computeLabel
                  newRight.left = r
                  rootLabelComputed = false
                  newRight
                // do not compute the label of newR, because it may still change
                case newRight =>
                  if (!rootLabelComputed) {
                    newRight.label = newRight.computeLabel
                    rootLabelComputed = true
                  }
                  r.right = newRight
                  r.label = r.computeLabel
                  r
              }
              (newR, true, rootLabelComputed)
            } else {
              // no change happened
              (r, false, true)
            }
          }
      }

    }

    var (newTopNode: ProverNodes, changeHappened: Boolean, rootLabelComputed: Boolean) = modifyHelper(topNode, foundIn = false)
    if (!rootLabelComputed) newTopNode.label = newTopNode.computeLabel
    topNode = newTopNode
    WTModifyProof(x, proofStream)
  }


  /*
    override def toString: String = {
      def mk(n: Node): String = {
        n.toString
        val ln = n.left.map(n => mk(n)).getOrElse("")
        val rn = n.right.map(n => mk(n)).getOrElse("")
        n.toString + "\n" + rn + ln
      }
      s"Wtree(${Base58.encode(rootHash()).take(8)}}): \n${mk(topNode)}"
    }
  */

}