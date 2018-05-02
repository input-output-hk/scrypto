package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.{Balance, _}
import scorex.crypto.hash.Digest
import scorex.utils.ByteArray

import scala.collection.mutable.ArrayBuffer
import scala.util.{Failure, Success, Try}


/**
  * Code common to the prover and verifier of https://eprint.iacr.org/2016/994
  * (see Appendix B, "Our Algorithms")
  */
trait AuthenticatedTreeOps[D <: Digest] extends BatchProofConstants with ToStringHelper {

  type ChangeHappened = Boolean
  type HeightIncreased = Boolean
  type ToDelete = Boolean

  protected val keyLength: Int
  protected val valueLengthOpt: Option[Int]
  protected val collectChangedNodes: Boolean
  /**
    * Sequence of leafs and internal nodes that where likely by modified after last proof generation
    */
  protected val changedNodesBuffer: ArrayBuffer[ProverNodes[D]] = ArrayBuffer.empty
  /**
    * Nodes that may, or may not be mofidied after last proof generation
    */
  protected val changedNodesBufferToCheck: ArrayBuffer[ProverNodes[D]] = ArrayBuffer.empty

  protected val PositiveInfinityKey: ADKey = ADKey @@ Array.fill(keyLength)(-1: Byte)
  protected val NegativeInfinityKey: ADKey = ADKey @@ Array.fill(keyLength)(0: Byte)

  protected var rootNodeHeight: Int

  protected def onNodeVisit(n: Node[D], operation: Operation, isRotate: Boolean = false): Unit = {
    n match {
      case p: ProverNodes[D] if collectChangedNodes && !n.visited && !p.isNew =>
        if (isRotate) {
          // during rotate operation node may stay in the tree in a different position
          changedNodesBufferToCheck += p
        } else if (operation.isInstanceOf[Insert] || operation.isInstanceOf[Remove]
          || operation.isInstanceOf[InsertOrUpdate]) {
          // during non-rotate insert and remove operations nodes on the path should not be presented in a new tree
          changedNodesBuffer += p
        } else if (!operation.isInstanceOf[Lookup]) {
          // during other non-lookup operations we don't know, whether node will stay in thee tree or not
          changedNodesBufferToCheck += p
        }
      case _ =>
    }
    n.visited = true
  }

  /**
    * The digest consists of the label of the root node followed by its height,
    * expressed as a single (unsigned) byte
    */
  protected def digest(rootNode: Node[D]): ADDigest = {
    assert(rootNodeHeight >= 0 && rootNodeHeight < 256)
    // rootNodeHeight should never be more than 255, so the toByte conversion is safe (though it may cause an incorrect
    // sign on the signed byte if rootHeight>127, but we handle that case correctly on decoding the byte back to int in the
    // verifier, by adding 256 if it's negative).
    // The reason rootNodeHeight should never be more than 255 is that if height is more than 255,
    // then the AVL tree has at least  2^{255/1.4405} = 2^177 leaves, which is more than the number of atoms on planet Earth.
    ADDigest @@ (rootNode.label :+ rootNodeHeight.toByte)
  }

  /* The following four methods differ for the prover and verifier, but are used in the code below */
  /**
    * @return - whether we found the correct leaf and the key contains it
    */
  protected def keyMatchesLeaf(key: ADKey, r: Leaf[D]): Boolean

  /**
    * @return - whether to go left or right when searching for key and standing at r
    */
  protected def nextDirectionIsLeft(key: ADKey, r: InternalNode[D]): Boolean

  /**
    * @return - a new node with two leaves: r on the left and a new leaf containing key and value on the right
    */
  protected def addNode(r: Leaf[D], key: ADKey, v: ADValue): InternalNode[D]

  /**
    * Deletions go down the tree twice -- once to find the leaf and realize
    * that it needs to be deleted, and the second time to actually perform the deletion.
    * This method will re-create comparison results. Each time it's called, it will give
    * the next comparison result of
    * key and node.key, where node starts at the root and progresses down the tree
    * according to the comparison results.
    *
    * @return - result of previous comparison of key and relevant node's key
    */
  protected def replayComparison: Int

  /**
    * Assumes the conditions for the double left rotation have already been established
    * and rightChild.left.visited = true
    * neither child needs to be attached to currentRoot
    */
  private def doubleLeftRotate(currentRoot: InternalNode[D], leftChild: Node[D], rightChild: InternalNode[D]): InternalNode[D] = {
    val newRoot = rightChild.left.asInstanceOf[InternalNode[D]]
    val (newLeftBalance: Balance, newRightBalance: Balance) = newRoot.balance match {
      case a if a == 0 =>
        (Balance @@ 0.toByte, Balance @@ 0.toByte)
      case a if a == -1 =>
        (Balance @@ 0.toByte, Balance @@ 1.toByte)
      case a if a == 1 =>
        (Balance @@ -1.toByte, Balance @@ 0.toByte)
    }
    val newLeftChild = currentRoot.getNew(newLeft = leftChild, newRight = newRoot.left, newBalance = newLeftBalance)
    val newRightChild = rightChild.getNew(newLeft = newRoot.right, newBalance = newRightBalance)
    newRoot.getNew(newLeft = newLeftChild, newRight = newRightChild, newBalance = Balance @@ 0.toByte)
  }

  /**
    * Assumes the conditions for the double right rotation have already been established
    * and leftChild.right.visited = true
    * neither child needs to be attached to currentRoot
    */
  private def doubleRightRotate(currentRoot: InternalNode[D], leftChild: InternalNode[D], rightChild: Node[D]): InternalNode[D] = {
    val newRoot = leftChild.right.asInstanceOf[InternalNode[D]]
    val (newLeftBalance: Balance, newRightBalance: Balance) = newRoot.balance match {
      case a if a == 0 =>
        (Balance @@ 0.toByte, Balance @@ 0.toByte)
      case a if a == -1 =>
        (Balance @@ 0.toByte, Balance @@ 1.toByte)
      case a if a == 1 =>
        (Balance @@ -1.toByte, Balance @@ 0.toByte)
    }
    val newRightChild = currentRoot.getNew(newRight = rightChild, newLeft = newRoot.right, newBalance = newRightBalance)
    val newLeftChild = leftChild.getNew(newRight = newRoot.left, newBalance = newLeftBalance)
    newRoot.getNew(newLeft = newLeftChild, newRight = newRightChild, newBalance = Balance @@ 0.toByte)
  }

  protected def returnResultOfOneOperation(operation: Operation, rootNode: Node[D]): Try[(Node[D], Option[ADValue])] = Try {
    val key = operation.key

    require(ByteArray.compare(key, NegativeInfinityKey) > 0, s"Key ${encoder.encode(key)} is less than -inf")
    require(ByteArray.compare(key, PositiveInfinityKey) < 0, s"Key ${encoder.encode(key)} is more than +inf")
    require(key.length == keyLength)

    var savedNode: Option[Leaf[D]] = None // The leaf to be saved in the hard deletion case, where we delete a leaf and copy its info over to another leaf


    /**
      * returns the new root, an indicator whether tree has been modified at r or below,
      * an indicator whether the height has increased,
      * an indicator whether we need to go delete the leaf that was just reached,
      * and the old value associated with key
      *
      * Handles binary tree search and AVL rebalancing
      *
      * Deletions are not handled here in order not to complicate the code even more -- in case of deletion,
      * we don't change the tree, but simply return toDelete = true.
      * We then go in and delete using deleteHelper
      */
    def modifyHelper(rNode: Node[D], key: ADKey, operation: Operation): (Node[D], ChangeHappened, HeightIncreased, ToDelete, Option[ADValue]) = {
      // Do not set the visited flag on the way down -- set it only after you know the operation did not fail,
      // because if the operation failed, there is no need to put nodes in the proof.
      rNode match {
        case r: Leaf[D] =>
          if (keyMatchesLeaf(key, r)) {
            operation match {
              case m: Modification =>
                m.updateFn(Some(r.value)) match {
                  case Success(None) => // delete key
                    onNodeVisit(r, operation)
                    (r, false, false, true, Some(r.value))
                  case Success(Some(v)) => // update value
                    valueLengthOpt.foreach(vl => require(v.length == vl, s"Value length is fixed and should be $vl"))
                    val oldValue = Some(r.value)
                    val rNew = r.getNew(newValue = v)
                    onNodeVisit(r, operation)
                    (rNew, true, false, false, oldValue)
                  case Failure(e) => // updateFunction doesn't like the value we found
                    throw e
                }
              case _: Lookup =>
                onNodeVisit(r, operation)
                (r, false, false, false, Some(r.value))
            }
          } else {
            // x > r.key
            operation match {
              case m: Modification =>
                m.updateFn(None) match {
                  case Success(None) => // don't change anything, just lookup
                    onNodeVisit(rNode, operation)
                    (r, false, false, false, None)
                  case Success(Some(v)) => // insert new value
                    valueLengthOpt.foreach(vl => require(v.length == vl, s"Value length is fixed and should be $vl"))
                    onNodeVisit(rNode, operation)
                    (addNode(r, key, v), true, true, false, None)
                  case Failure(e) => // updateFunctions doesn't like that we found nothing
                    throw e
                }
              case _: Lookup =>
                onNodeVisit(rNode, operation)
                (r, false, false, false, None)
            }
          }
        case r: InternalNode[D] =>
          // Go recursively in the correct direction
          // Get a new node
          // See if a single or double rotation is needed for AVL tree balancing
          if (nextDirectionIsLeft(key, r)) {
            val (newLeftM, changeHappened, childHeightIncreased, toDelete, oldValue) = modifyHelper(r.left, key, operation)
            onNodeVisit(r, operation)

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              if (childHeightIncreased && r.balance < 0) {
                // need to rotate
                // at this point we know newLeftM must be an internal node and not a leaf -- because height increased
                val newLeft = newLeftM.asInstanceOf[InternalNode[D]]
                if (newLeft.balance < 0) {
                  // single right rotate
                  val newR = r.getNew(newLeft = newLeft.right, newBalance = Balance @@ 0.toByte)
                  (newLeft.getNew(newRight = newR, newBalance = Balance @@ 0.toByte), true, false, false, oldValue)
                } else {
                  (doubleRightRotate(r, newLeft, r.right), true, false, false, oldValue)
                }
              } else {
                // no need to rotate
                val myHeightIncreased = childHeightIncreased && r.balance == (0: Byte)
                val rBalance = if (childHeightIncreased) Balance @@ (r.balance - 1).toByte else r.balance
                (r.getNew(newLeft = newLeftM, newBalance = rBalance), true, myHeightIncreased, false, oldValue)
              }

            } else {
              // no change happened
              (r, false, false, toDelete, oldValue)
            }
          } else {
            val (newRightM, changeHappened, childHeightIncreased, toDelete, oldValue) = modifyHelper(r.right, key, operation)
            onNodeVisit(r, operation)

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              if (childHeightIncreased && r.balance > 0) {
                // need to rotate
                // at this point we know newRightM must be an internal node and not a leaf -- because height increased
                val newRight = newRightM.asInstanceOf[InternalNode[D]]

                if (newRight.balance > 0) {
                  // single left rotate
                  val newR = r.getNew(newRight = newRight.left, newBalance = Balance @@ 0.toByte)
                  (newRight.getNew(newLeft = newR, newBalance = Balance @@ 0.toByte), true, false, false, oldValue)
                } else {
                  (doubleLeftRotate(r, r.left, newRight), true, false, false, oldValue)
                }
              } else {
                // no need to rotate
                val myHeightIncreased: Boolean = childHeightIncreased && r.balance == (0: Byte)
                val rBalance = if (childHeightIncreased) Balance @@ (r.balance + 1).toByte else r.balance
                (r.getNew(newRight = newRightM, newBalance = rBalance), true, myHeightIncreased, false, oldValue)
              }
            } else {
              // no change happened
              (r, false, false, toDelete, oldValue)
            }
          }
        case r: LabelOnlyNode[D] =>
          throw new Error("Should never reach this point. If in prover, this is a bug. If in verifier, this proof is wrong.")
      }
    }

    /** Deletes the node in the subtree rooted at r and its corresponding leaf
      * as indicated by replayComparison or deleteMax. Performs AVL balancing.
      *
      * If deleteMax == false: deletes the first node for which replayComparison returns 0
      * and the leaf that is the leftmost descendant of this node's child
      *
      * If deleteMax == true: deletes the right leaf and its parent, replacing the parent
      * with the parent's left child
      *
      * Returns the new root and an indicator whether the tree height decreased
      */
    def deleteHelper(r: InternalNode[D], deleteMax: Boolean): (Node[D], Boolean) = {
      // Overall strategy: if key is found in the node that has only a leaf as either
      // of the two children, we can just delete the node. If it has a leaf as the right child,
      // we can also delete the right child, update the nextLeafKey in the rightmost leaf of the left subtree,
      // and we are done. Else, it has a leaf as the left child,
      // so we copy the information from this left child leaf to the leftmost leaf in the right subtree,
      // and delete the left child.
      //
      // Things get more complicated key is found in a node that has two non-leaf children.
      // In that case, we perform a deleteMax operation on the left subtree
      // (recursively call ourselves on the left child with
      // with deleteMax = true), and copy the information from that deleted leaf into the node where the
      // key was found and into the leftmost leaf of its right subtree

      def changeNextLeafKeyOfMaxNode(rNode: Node[D], nextLeafKey: ADKey): Node[D] = {
        onNodeVisit(rNode, operation)
        rNode match {
          case leaf: Leaf[D] =>
            leaf.getNew(newNextLeafKey = nextLeafKey)
          case rN: InternalNode[D] =>
            rN.getNew(newRight = changeNextLeafKeyOfMaxNode(rN.right, nextLeafKey))
          case rN: LabelOnlyNode[D] =>
            throw new Error("Should never reach this point. If in prover, this is a bug. In in verifier, this proof is wrong.")
        }
      }

      def changeKeyAndValueOfMinNode(rNode: Node[D], newKey: ADKey, newValue: ADValue): Node[D] = {
        onNodeVisit(rNode, operation)
        rNode match {
          case leaf: Leaf[D] =>
            leaf.getNew(newKey = newKey, newValue = newValue)
          case rN: InternalNode[D] =>
            rN.getNew(newLeft = changeKeyAndValueOfMinNode(rN.left, newKey, newValue))
          case rN: LabelOnlyNode[D] =>
            throw new Error("Should never reach this point. If in prover, this is a bug. If in verifier, this proof is wrong.")
        }
      }

      onNodeVisit(r, operation)

      val direction = if (deleteMax) 1 else replayComparison

      assert(!(direction < 0 && r.left.isInstanceOf[Leaf[D]]))
      // If direction<0, this means we are not in deleteMax mode and we still haven't found
      // the value we are trying to delete
      // If the next step -- which is to the left -- is a leaf, then the value
      // we are looking for is not a key of any internal node in the tree,
      // which is impossible

      if (direction >= 0 && r.right.isInstanceOf[Leaf[D]]) {
        // we delete this node and its right child (leaf)
        // we return the left subtree
        val rightChild = r.right.asInstanceOf[Leaf[D]]
        onNodeVisit(rightChild, operation)
        if (deleteMax) {
          // If we are in deleteMax mode,
          // we should save the info of leaf we are deleting,
          // because it will be copied over to its successor
          savedNode = Some(rightChild)
          (r.left, true)
        } else {
          // Otherwise, we really are deleting the leaf, and therefore
          // we need to change the nextLeafKey of its predecessor
          assert(direction == 0)
          (changeNextLeafKeyOfMaxNode(r.left, rightChild.nextLeafKey), true)
        }
      } else if (direction == 0 && r.left.isInstanceOf[Leaf[D]]) {
        // we know (r.left.isInstanceOf[Leaf])
        // we delete the node and its left child (leaf); we return the right
        // subtree, after changing the key and value stored in its leftmost leaf
        val leftChild = r.left.asInstanceOf[Leaf[D]]
        onNodeVisit(leftChild, operation)
        (changeKeyAndValueOfMinNode(r.right, leftChild.key, leftChild.value), true)
      } else {
        // Potential hard deletion cases:
        if (direction <= 0) {
          // going left; know left child is not a leaf; deleteMax if and only if direction == 0
          val (newLeft, childHeightDecreased) = deleteHelper(r.left.asInstanceOf[InternalNode[D]], direction == 0)

          val newRoot = if (direction == 0) {
            // this is the case where we needed to delete the min of the right
            // subtree, but, because we had two non-leaf children,
            // we instead deleted the node that was the max of the left subtree
            // and are copying its info
            val s = savedNode.get
            savedNode = None
            val rWithChangedKey = r.getNewKey(s.key)
            rWithChangedKey.getNew(newRight = changeKeyAndValueOfMinNode(rWithChangedKey.right, s.key, s.value))
          } else {
            r
          }

          if (childHeightDecreased && newRoot.balance > 0) {
            // new to rotate because my left subtree is shorter than my right
            onNodeVisit(newRoot.right, operation, isRotate = true)

            // I know my right child is not a leaf, because it is taller than my left
            val rightChild = newRoot.right.asInstanceOf[InternalNode[D]]
            if (rightChild.balance < 0) {
              // double left rotate
              // I know rightChild.left is not a leaf, because rightChild has a higher subtree on the left
              onNodeVisit(rightChild.left, operation, isRotate = true)
              (doubleLeftRotate(newRoot, newLeft, rightChild), true)
            } else {
              // single left rotate
              val newLeftChild = newRoot.getNew(newLeft = newLeft, newRight = rightChild.left,
                newBalance = Balance @@ (1 - rightChild.balance).toByte)
              val newR = rightChild.getNew(newLeft = newLeftChild,
                newBalance = Balance @@ (rightChild.balance - 1).toByte)
              (newR, newR.balance == 0)
            }
          } else {
            // no rotation, just recalculate newRoot.balance and childHeightDecreased
            val newBalance = if (childHeightDecreased) Balance @@ (newRoot.balance + 1).toByte else newRoot.balance
            (newRoot.getNew(newLeft = newLeft, newBalance = newBalance), childHeightDecreased && newBalance == 0)
          }
        } else {
          // going right; know right child is not a leaf
          val (newRight, childHeightDecreased) = deleteHelper(r.right.asInstanceOf[InternalNode[D]], deleteMax)
          if (childHeightDecreased && r.balance < 0) {
            // new to rotate because my right subtree is shorter than my left
            onNodeVisit(r.left, operation, isRotate = true)

            // I know my left child is not a leaf, because it is taller than my right
            val leftChild = r.left.asInstanceOf[InternalNode[D]]
            if (leftChild.balance > 0) {
              // double right rotate
              // I know leftChild.right is not a leaf, because leftChild has a higher subtree on the right
              onNodeVisit(leftChild.right, operation, isRotate = true)
              (doubleRightRotate(r, leftChild, newRight), true)
            } else {
              // single right rotate
              val newRightChild = r.getNew(newLeft = leftChild.right, newRight = newRight,
                newBalance = Balance @@ (-leftChild.balance - 1).toByte)
              val newR = leftChild.getNew(newRight = newRightChild,
                newBalance = Balance @@ (1 + leftChild.balance).toByte)
              (newR, newR.balance == 0)
            }
          } else {
            // no rotation, just recalculate r.balance and childHeightDecreased
            val newBalance = if (childHeightDecreased) Balance @@ (r.balance - 1).toByte else r.balance
            (r.getNew(newRight = newRight, newBalance = newBalance), childHeightDecreased && newBalance == 0)
          }
        }
      }
    }

    val (newRootNode, _, heightIncreased, toDelete, oldValue) = modifyHelper(rootNode, key, operation)
    if (toDelete) {
      val (postDeleteRootNode, heightDecreased) = deleteHelper(newRootNode.asInstanceOf[InternalNode[D]], deleteMax = false)
      if (heightDecreased) rootNodeHeight -= 1
      (postDeleteRootNode, oldValue)
    } else {
      if (heightIncreased) rootNodeHeight += 1
      (newRootNode, oldValue)
    }
  }
}