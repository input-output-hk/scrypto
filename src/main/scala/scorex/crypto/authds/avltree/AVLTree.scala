package scorex.crypto.authds.avltree

import scorex.crypto.authds._
import scorex.crypto.hash.{Blake2b256Unsafe, CryptographicHash}
import scorex.utils.ByteArray


class AVLTree[HF <: CryptographicHash](rootOpt: Option[Leaf] = None)
                                      (implicit hf: HF = Blake2b256Unsafe) extends TwoPartyDictionary[AVLKey, AVLValue] {

  var topNode: ProverNodes = rootOpt.getOrElse(Leaf(NegativeInfinity._1, NegativeInfinity._2, PositiveInfinity._1))

  def rootHash(): Label = topNode.label



  // We could add return values here:
  // - we could return boolean indicating whether x was found
  // - we could val or newVal
  // - more generally, we could return the result of updateFunction (which could have its own return type,
  // for example returning both old value and new value, or some sort of success/failure)
  // I am not sure what's needed in the application
  //TODO insert toInsertIfNotFound to function
  def modify(key: AVLKey, updateFunction: UpdateFunction, toInsertIfNotFound: Boolean = true): AVLModifyProof = {
    require(ByteArray.compare(key, NegativeInfinity._1) > 0)
    require(ByteArray.compare(key, PositiveInfinity._1) < 0)

    val proofStream = new scala.collection.mutable.Queue[AVLProofElement]

    // found tells us if x has been already found above r in the tree
    // returns the new root
    // and an indicator whether tree has been modified at r or below
    def modifyHelper(rNode: ProverNodes, foundAbove: Boolean): (ProverNodes, Boolean, Boolean) = {
      rNode match {
        case r: Leaf =>
          if (foundAbove) {
            // we already know it's in the tree, so it must be at the current leaf
            proofStream.enqueue(ProofDirection(LeafFound))
            proofStream.enqueue(ProofNextLeafKey(r.nextLeafKey))
            proofStream.enqueue(ProofValue(r.value))
            r.value = updateFunction(Some(r.value))
            (r, true, false)
          } else {
            // x > r.key
            proofStream.enqueue(ProofDirection(LeafNotFound))
            proofStream.enqueue(ProofKey(r.key))
            proofStream.enqueue(ProofNextLeafKey(r.nextLeafKey))
            proofStream.enqueue(ProofValue(r.value))
            if (toInsertIfNotFound) {
              val newLeaf = new Leaf(key, updateFunction(None), r.nextLeafKey)
              r.nextLeafKey = key
              (ProverNode(key, r, newLeaf), true, true)
            } else {
              (r, false, false)
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
          // See if a single or double rotation is needed for AVL tree balancing
          if (nextStepIsLeft) {
            proofStream.enqueue(ProofDirection(GoingLeft))
            proofStream.enqueue(ProofRightLabel(r.rightLabel))
            proofStream.enqueue(ProofBalance(r.balance))

            var (newLeftM: ProverNodes, changeHappened: Boolean, childHeightIncreased: Boolean) = modifyHelper(r.left, found)

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              if (childHeightIncreased && r.balance < 0) {
                // need to rotate
                newLeftM match {
                  // at this point we know newleftM must be an internal node an not a leaf -- b/c height increased;  TODO: make this more scala-like
                  case newLeft: ProverNode =>
                    if (newLeft.balance < 0) {
                      // single rotate
                      r.left = newLeft.right
                      r.balance = 0
                      newLeft.right = r
                      newLeft.balance = 0
                      assert(r.checkHeight)
                      assert(newLeft.checkHeight)
                      (newLeft, true, false)
                    }

                    else { 
                      // double rotate
                      val newRootM = newLeft.right
                      assert (newRootM.isInstanceOf[ProverNode])
                      val newRoot = newRootM.asInstanceOf[ProverNode]

                      assert(newLeft.balance>0)

                      r.left = newRoot.right
                      newRoot.right = r
                      newLeft.right = newRoot.left
                      newRoot.left = newLeft
                      
                      newRoot.balance match {
                        case 0 =>
                          // newRoot is a newly created node
                          assert (r.left.isInstanceOf[Leaf] && r.right.isInstanceOf[Leaf])
                          assert (newLeft.left.isInstanceOf[Leaf] && newLeft.right.isInstanceOf[Leaf])
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
                      
                      assert(r.checkHeight)
                      assert(newLeft.checkHeight)
                      assert(newRoot.checkHeight)

                      (newRoot, true, false)
                    }
                  case newLeft =>
                    assert(false) // TODO : make this more scala-like
                    (r, true, false) // TODO: this return value is not needed
                }
              } else {
                // no need to rotate
                r.left = newLeftM
                val myHeightIncreased: Boolean = childHeightIncreased && r.balance == 0
                if (childHeightIncreased) r.balance -= 1
                assert(r.checkHeight)

                (r, true, myHeightIncreased)
              }

            } else {
              // no change happened
              assert(r.checkHeight)
              (r, false, false)
            }
          } else {
            // next step is to the right
            proofStream.enqueue(ProofDirection(GoingRight))
            proofStream.enqueue(ProofLeftLabel(r.leftLabel))
            proofStream.enqueue(ProofBalance(r.balance))
            var (newRightM: ProverNodes, changeHappened: Boolean, childHeightIncreased: Boolean) = modifyHelper(r.right, found)

            if (changeHappened) {
              if (childHeightIncreased && r.balance > 0) {
                // need to rotate
                newRightM match {
                  // at this point we know newRightM must be an internal node and not a leaf -- because height increased;  TODO: make this more scala-like
                  case newRight: ProverNode =>
                    if (newRight.balance > 0) {
                      // single rotate
                      r.right = newRight.left
                      r.balance = 0
                      newRight.left = r
                      newRight.balance = 0
                      assert(r.checkHeight)
                      assert(newRight.checkHeight)
                      (newRight, true, false)
                    }

                    else { 
                      // double rotate
                      val newRootM = newRight.left
                      assert (newRootM.isInstanceOf[ProverNode])
                      val newRoot = newRootM.asInstanceOf[ProverNode]

                      assert(newRight.balance<0)

                      r.right = newRoot.left
                      newRoot.left = r
                      newRight.left = newRoot.right
                      newRoot.right = newRight
                      
                     newRoot.balance match {
                        case 0 =>
                          // newRoot is an newly created node
                          assert (r.left.isInstanceOf[Leaf] && r.right.isInstanceOf[Leaf])
                          assert (newRight.left.isInstanceOf[Leaf] && newRight.right.isInstanceOf[Leaf])
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
                        
                      assert(r.checkHeight)
                      assert(newRight.checkHeight)
                      assert(newRoot.checkHeight)

                      (newRoot, true, false)
                    }
                  case newRight =>
                    assert(false) // TODO : make this more scala-like
                    (r, true, false) // TODO: this return value is not needed
                }
              } else {
                // no need to rotate
                r.right = newRightM
                val myHeightIncreased: Boolean = (childHeightIncreased && r.balance == 0)
                if (childHeightIncreased) r.balance += 1
                assert(r.checkHeight)
                (r, true, myHeightIncreased)
              }
            } else {
              // no change happened
              assert(r.checkHeight)
              (r, false, false)
            }
          }
      }
    }

    val (newTopNode: ProverNodes, changeHappened: Boolean, childHeightIncreased: Boolean) = modifyHelper(topNode, foundAbove = false)
    if (changeHappened) topNode = newTopNode // TODO MAKE SAME CHANGE IN OTHER TREES OR REMOVE IT HERE
    AVLModifyProof(key, proofStream)
  }

}
