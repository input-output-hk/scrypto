package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.avltree.{AVLKey, AVLValue}
import scorex.crypto.encode.Base58
import scorex.utils.{ByteArray, ScryptoLogging}

import scala.util.{Failure, Success}


trait AuthenticatedTreeOps extends BatchProofConstants with ScryptoLogging {

  type ChangeHappened = Boolean
  type HeightIncreased = Boolean
  type ToDelete = Boolean

  protected val keyLength: Int
  protected val valueLength: Int

  protected val PositiveInfinityKey: Array[Byte] = Array.fill(keyLength)(-1: Byte)
  protected val NegativeInfinityKey: Array[Byte] = Array.fill(keyLength)(0: Byte)

  protected var rootNodeHeight: Int

  // The digest consists of the label of the root node followed by its height, expressed as a single (unsigned) byte
  protected def digest(rootNode: Node): Array[Byte] = {
    assert(rootNodeHeight >= 0 && rootNodeHeight < 256)
    // rootNodeHeight should never be more than 255, so the toByte conversion is safe (though it may cause an incorrect
    // sign on the signed byte if rootHeight>127, but we handle that case correctly on decoding the byte back to int in the
    // verifier, by adding 256 if it's negative).
    // The reason rootNodeHeight should never be more than 255 is that if height is more than 255,
    // then the AVL tree has at least  2^{255/1.4405} = 2^177 leaves, which is more than the number of atoms on planet Earth.
    rootNode.label :+ rootNodeHeight.toByte
  }

  protected def replayComparison: Int

  protected def keyMatchesLeaf(key: AVLKey, r: Leaf): Boolean

  protected def nextDirectionIsLeft(key: AVLKey, r: InternalNode): Boolean

  protected def addNode(r: Leaf, key: AVLKey, v: AVLValue): InternalNode

  /**
    * Assumes the conditions for the double left rotation have already been established
    * and rightChild.left.visited = true
    * neither child needs to be attached to currentRoot
    */
  private def doubleLeftRotate(currentRoot: InternalNode, leftChild: Node, rightChild: InternalNode): InternalNode = {
    val newRoot = rightChild.left.asInstanceOf[InternalNode]
    val (newLeftBalance, newRightBalance) = newRoot.balance match {
      case 0 =>
        (0: Byte, 0: Byte)
      case -1 =>
        (0: Byte, 1: Byte)
      case 1 =>
        (-1: Byte, 0: Byte)
    }
    val newLeftChild = currentRoot.getNew(newLeft = leftChild, newRight = newRoot.left, newBalance = newLeftBalance)
    val newRightChild = rightChild.getNew(newLeft = newRoot.right, newBalance = newRightBalance)
    newRoot.getNew(newLeft = newLeftChild, newRight = newRightChild, newBalance = 0.toByte)
  }

  /**
    * Assumes the conditions for the double right rotation have already been established
    * and leftChild.right.visited = true
    * neither child needs to be attached to currentRoot
    */
  private def doubleRightRotate(currentRoot: InternalNode, leftChild: InternalNode, rightChild: Node): InternalNode = {
    val newRoot = leftChild.right.asInstanceOf[InternalNode]
    val (newLeftBalance, newRightBalance) = newRoot.balance match {
      case 0 =>
        (0: Byte, 0: Byte)
      case -1 =>
        (0: Byte, 1: Byte)
      case 1 =>
        (-1: Byte, 0: Byte)
    }
    val newRightChild = currentRoot.getNew(newRight = rightChild, newLeft = newRoot.right, newBalance = newRightBalance)
    val newLeftChild = leftChild.getNew(newRight = newRoot.left, newBalance = newLeftBalance)
    newRoot.getNew(newLeft = newLeftChild, newRight = newRightChild, newBalance = 0.toByte)
  }

  protected def returnResultOfOneModification[M <: Modification](modification: M, rootNode: Node): Node = {
    val key = modification.key
    val updateFunction = modification.updateFn

    require(ByteArray.compare(key, NegativeInfinityKey) > 0, s"Key ${Base58.encode(key)} is less than -inf")
    require(ByteArray.compare(key, PositiveInfinityKey) < 0, s"Key ${Base58.encode(key)} is more than +inf")
    require(key.length == keyLength)

    var savedNode: Option[Leaf] = None // The leaf to be saved in the hard deletion case, where we delete a leaf and copy its info over to another leaf

    /** Deletes the node in the subtree rooted at r and its corresponding leaf
      * as indicated by replayDirections or deleteMax. Performs AVL balancing.
      *
      * If deleteMax == false: deletes the first node for which replayDirections returns 0
      * and the leaf that is the leftmost descendant of this node's child
      *
      * If deleteMax == true: deletes the right leaf and its parent, replacing the parent
      * with the parent's left child
      *
      * Returns the new root and an indicator whether the tree height decreased
      */

    /**
      * returns the new root, an indicator whether tree has been modified at r or below,
      * an indicator whether the height has increased,
      * and an indicator whether we need to go delete the leaf that was just reached
      */
    def modifyHelper(rNode: Node, key: AVLKey, updateFunction: Modification#UpdateFunction): (Node, ChangeHappened, HeightIncreased, ToDelete) = {
      rNode match {
        case r: Leaf =>
          if (keyMatchesLeaf(key, r)) {
            updateFunction(Some(r.value)) match {
              case Success(None) => // delete key
                r.visited = true
                (r, false, false, true)
              case Success(Some(v)) => // update value
                r.visited = true
                require(v.length == valueLength)
                val rNew = r.getNew(newValue = v)
                (rNew, true, false, false)
              case Failure(e) => // updateFunction doesn't like the value we found
                throw e
            }
          } else {
            // x > r.key
            updateFunction(None) match {
              case Success(None) => // don't change anything, just lookup
                rNode.visited = true
                (r, false, false, false)
              case Success(Some(v)) => // insert new value
                rNode.visited = true
                require(v.length == valueLength)
                (addNode(r, key, v), true, true, false)
              case Failure(e) => // updateFunctions doesn't like that we found nothing
                throw e
            }
          }
        case r: InternalNode =>
          // Go recursively in the correct direction
          // Get a new node
          // See if a single or double rotation is needed for AVL tree balancing
          if (nextDirectionIsLeft(key, r)) {
            val (newLeftM, changeHappened, childHeightIncreased, toDelete) = modifyHelper(r.left, key, updateFunction)
            r.visited = true

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              if (childHeightIncreased && r.balance < 0) {
                // need to rotate
                // at this point we know newleftM must be an internal node and not a leaf -- because height increased
                val newLeft = newLeftM.asInstanceOf[InternalNode]
                if (newLeft.balance < 0) {
                  // single right rotate
                  val newR = r.getNew(newLeft = newLeft.right, newBalance = 0: Byte)
                  (newLeft.getNew(newRight = newR, newBalance = 0: Byte), true, false, false)
                } else {
                  (doubleRightRotate(r, newLeft, r.right), true, false, false)
                }
              } else {
                // no need to rotate
                val myHeightIncreased = childHeightIncreased && r.balance == (0: Byte)
                val rBalance = if (childHeightIncreased) (r.balance - 1).toByte else r.balance
                (r.getNew(newLeft = newLeftM, newBalance = rBalance), true, myHeightIncreased, false)
              }

            } else {
              // no change happened
              (r, false, false, toDelete)
            }
          } else {
            val (newRightM, changeHappened, childHeightIncreased, toDelete) = modifyHelper(r.right, key, updateFunction)
            r.visited = true

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              if (childHeightIncreased && r.balance > 0) {
                // need to rotate
                // at this point we know newRightM must be an internal node and not a leaf -- because height increased
                val newRight = newRightM.asInstanceOf[InternalNode]

                if (newRight.balance > 0) {
                  // single left rotate
                  val newR = r.getNew(newRight = newRight.left, newBalance = 0: Byte)
                  (newRight.getNew(newLeft = newR, newBalance = 0: Byte), true, false, false)
                } else {
                  (doubleLeftRotate(r, r.left, newRight), true, false, false)
                }
              } else {
                // no need to rotate
                val myHeightIncreased: Boolean = childHeightIncreased && r.balance == (0: Byte)
                val rBalance = if (childHeightIncreased) (r.balance + 1).toByte else r.balance
                (r.getNew(newRight = newRightM, newBalance = rBalance), true, myHeightIncreased, false)
              }
            } else {
              // no change happened
              (r, false, false, toDelete)
            }
          }
        case r: LabelOnlyNode =>
          throw new Error("Should never reach this point. If in prover, this is a bug. If in verifier, this proof is wrong.")
      }
    }

    def deleteHelper(r: InternalNode, deleteMax: Boolean): (Node, Boolean) = {
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

      def changeNextLeafKeyOfMaxNode(rNode: Node, nextLeafKey: AVLKey): Node = {
        rNode.visited = true
        rNode match {
          case leaf: Leaf =>
            leaf.getNew(newNextLeafKey = nextLeafKey)
          case rN: InternalNode =>
            rN.getNew(newRight = changeNextLeafKeyOfMaxNode(rN.right, nextLeafKey))
          case rN: LabelOnlyNode =>
            throw new Error("Should never reach this point. If in prover, this is a bug. In in verifier, this proof is wrong.")
        }
      }

      def changeKeyAndValueOfMinNode(rNode: Node, newKey: AVLKey, newValue: AVLValue): Node = {
        rNode.visited = true
        rNode match {
          case leaf: Leaf =>
            leaf.getNew(newKey = newKey, newValue = newValue)
          case rN: InternalNode =>
            rN.getNew(newLeft = changeKeyAndValueOfMinNode(rN.left, newKey, newValue))
          case rN: LabelOnlyNode =>
            throw new Error("Should never reach this point. If in prover, this is a bug. If in verifier, this proof is wrong.")
        }
      }

      r.visited = true

      val direction = if (deleteMax) 1 else replayComparison

      assert(!(direction < 0 && r.left.isInstanceOf[Leaf]))
      // If direction<0, this means we are not in deleteMax mode and we still haven't found
      // the value we are trying to delete
      // If the next step -- which is to the left -- is a leaf, then the value
      // we are looking for is not a key of any internal node in the tree,
      // which is impossible

      if (direction >= 0 && r.right.isInstanceOf[Leaf]) {
        // we delete this node and its right child (leaf)
        // we return the left subtree
        val rightChild = r.right.asInstanceOf[Leaf]
        rightChild.visited = true
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
      } else if (direction == 0 && r.left.isInstanceOf[Leaf]) {
        // we know (r.left.isInstanceOf[Leaf])
        // we delete the node and its left child (leaf); we return the right
        // subtree, after changing the key and value stored in its leftmost leaf
        val leftChild = r.left.asInstanceOf[Leaf]
        leftChild.visited = true
        (changeKeyAndValueOfMinNode(r.right, leftChild.key, leftChild.value), true)
      } else {
        // Potential hard deletion cases:
        if (direction <= 0) {
          // going left; know left child is not a leaf; deleteMax if and only if direction == 0
          val (newLeft, childHeightDecreased) = deleteHelper(r.left.asInstanceOf[InternalNode], direction == 0)

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
            newRoot.right.visited = true
            // I know my right child is not a leaf, because it is taller than my left
            val rightChild = newRoot.right.asInstanceOf[InternalNode]
            if (rightChild.balance < 0) {
              // double left rotate
              // I know rightChild.left is not a leaf, because rightChild has a higher subtree on the left
              rightChild.left.visited = true
              (doubleLeftRotate(newRoot, newLeft, rightChild), true)
            } else {
              // single left rotate
              val newLeftChild = newRoot.getNew(newLeft = newLeft, newRight = rightChild.left, newBalance = (1 - rightChild.balance).toByte)
              val newR = rightChild.getNew(newLeft = newLeftChild, newBalance = (rightChild.balance - 1).toByte)
              (newR, newR.balance == 0)
            }
          } else {
            // no rotation, just recalculate newRoot.balance and childHeightDecreased
            val newBalance = if (childHeightDecreased) (newRoot.balance + 1).toByte else newRoot.balance
            (newRoot.getNew(newLeft = newLeft, newBalance = newBalance), childHeightDecreased && newBalance == 0)
          }
        } else {
          // going right; know right child is not a leaf
          val (newRight, childHeightDecreased) = deleteHelper(r.right.asInstanceOf[InternalNode], deleteMax)
          if (childHeightDecreased && r.balance < 0) {
            // new to rotate because my right subtree is shorter than my left
            r.left.visited = true
            // I know my left child is not a leaf, because it is taller than my right
            val leftChild = r.left.asInstanceOf[InternalNode]
            if (leftChild.balance > 0) {
              // double right rotate
              // I know leftChild.right is not a leaf, because leftChild has a higher subtree on the right
              leftChild.right.visited = true
              (doubleRightRotate(r, leftChild, newRight), true)
            } else {
              // single right rotate
              val newRightChild = r.getNew(newLeft = leftChild.right, newRight = newRight, newBalance = (-leftChild.balance - 1).toByte)
              val newR = leftChild.getNew(newRight = newRightChild, newBalance = (1 + leftChild.balance).toByte)
              (newR, newR.balance == 0)
            }
          } else {
            // no rotation, just recalculate r.balance and childHeightDecreased
            val newBalance = if (childHeightDecreased) (r.balance - 1).toByte else r.balance
            (r.getNew(newRight = newRight, newBalance = newBalance), childHeightDecreased && newBalance == 0)
          }
        }
      }
    }

    val (newRootNode, _, heightIncreased, toDelete) = modifyHelper(rootNode, key, updateFunction)
    if (toDelete) {
      val (postDeleteRootNode, heightDecreased) = deleteHelper(newRootNode.asInstanceOf[InternalNode], deleteMax = false)
      if (heightDecreased) rootNodeHeight -= 1
      postDeleteRootNode
    } else {
      if (heightIncreased) rootNodeHeight += 1
      newRootNode
    }
  }
}