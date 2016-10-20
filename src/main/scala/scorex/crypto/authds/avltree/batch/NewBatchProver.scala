package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree._
import scorex.utils.Random

import scala.util.{Failure, Success, Try}

import scorex.crypto.authds._
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray

import scala.util.{Failure, Success, Try}
import scala.collection.mutable


// TODO: interfaces/inheritance/signatures

case class NewBatchProof (packedTree : Seq[AVLProofElement], directions: Seq[Boolean]) 

class NewBatchProver[HF <: ThreadUnsafeHash](keyLength: Int, rootOpt: Option[Leaf] = None)
                                     (implicit hf: HF = new Blake2b256Unsafe) /*extends ADSUser*/ /* extends TwoPartyDictionary[AVLKey, AVLValue, AVLModifyProof] */ extends UpdateF[Array[Byte]]{
                                     
  private val PositiveInfinity: (Array[Byte], Array[Byte]) = (Array.fill(keyLength)(-1: Byte), Array())
  private val NegativeInfinity: (Array[Byte], Array[Byte]) = (Array.fill(keyLength)(0: Byte), Array())
  private var topNode: ProverNodes = rootOpt.getOrElse(Leaf(NegativeInfinity._1, NegativeInfinity._2, PositiveInfinity._1))
  private var oldTopNode = topNode
  private var proofStream = new scala.collection.mutable.ArrayBuffer[Boolean] // TODO: WHICH BUFFER TO USE
  private val newNodes = new scala.collection.mutable.ListBuffer[ProverNodes] // TODO: WHICH BUFFER TO USE

  def rootHash : Label = topNode.label

  def performOneModification(key: AVLKey, updateFunction: UpdateFunction) = {
    require(ByteArray.compare(key, NegativeInfinity._1) > 0, s"Key ${Base58.encode(key)} is less than -inf")
    require(ByteArray.compare(key, PositiveInfinity._1) < 0, s"Key ${Base58.encode(key)} is more than +inf")
    require(key.length == keyLength)


    /**
      * foundAbove tells us if x has been already found above r in the tree
      * returns the new root and an indicator whether tree has been modified at r or below
      *
      */
    def modifyHelper(rNode: ProverNodes, foundAbove: Boolean): (ProverNodes, Boolean, Boolean) = {
      rNode.visited = true
      rNode match {
        case r: Leaf =>
          if (foundAbove) {
            // we already know it's in the tree, so it must be at the current leaf
            updateFunction(Some(r.value)) match {
              case Success(None) => //delete value
                ???
              case Success(Some(v)) => //update value
                val rNew = r.changeValue(r.value, newNodes)
                (rNew, true, false)
              case Failure(e) => // found incorrect value
                throw e
            }
          } else {
            // x > r.key
            updateFunction(None) match {
              case Success(None) => //don't change anything, just lookup
                (r, false, false)
              case Success(Some(v)) => // insert new value
                val newLeaf = new Leaf(key, v, r.nextLeafKey)
                newNodes += newLeaf
                val oldLeaf = r.changeNextKey(key, newNodes)
                val newProverNode = new ProverNode(key, oldLeaf, newLeaf, 0)
                newNodes += newProverNode
                (newProverNode, true, true)
              case Failure(e) => // found incorrect value
                throw e
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
            proofStream += true

            val (newLeftM, changeHappened, childHeightIncreased) = modifyHelper(r.left, found)

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              // newLeftM should be new, because change happened
              // That's how we know we can make changes to newLeftM
              assert(newLeftM.isNew)
              if (childHeightIncreased && r.balance < 0) {
                // need to rotate
                // at this point we know newleftM must be an internal node and not a leaf -- because height increased;
                assert(newLeftM.isInstanceOf[ProverNode])
                val newLeft = newLeftM.asInstanceOf[ProverNode]
            
                if (newLeft.balance < 0) {
                  // single rotate
                  val newR = r.changeLeft(newLeft.right, 0: Byte, newNodes)
                  newLeft.right = newR
                  newLeft.balance = 0: Byte
                  assert(newR.checkHeight)
                  assert(newLeft.checkHeight)
                  (newLeft, true, false)
                } else {
                  // double rotate
                  val newRootM = newLeft.right
                  assert(newRootM.isInstanceOf[ProverNode])
                  val newRoot = newRootM.asInstanceOf[ProverNode]
                  assert(newRoot.isNew) // that's how we know we can change values in newRoot

                  assert(newLeft.balance > 0)
                  val rBalance = newRoot.balance match {
                    case 0 =>
                      // newRoot is a newly created node right above two leaves following an insert
                      assert(r.left.isInstanceOf[Leaf] && r.right.isInstanceOf[Leaf])
                      assert(newLeft.left.isInstanceOf[Leaf] && newLeft.right.isInstanceOf[Leaf])
                      newLeft.balance = 0: Byte
                      0: Byte
                    case -1 =>
                      newLeft.balance = 0: Byte
                      1: Byte
                    case 1 =>
                      newLeft.balance = -1: Byte
                      0: Byte
                  }
                  newRoot.balance = 0: Byte
              
                  val newR = r.changeLeft(newRoot.right, rBalance, newNodes)
                  newRoot.right = newR
                  newLeft.right = newRoot.left
                  newRoot.left = newLeft

                  assert(newR.checkHeight)
                  assert(newLeft.checkHeight)
                  assert(newRoot.checkHeight)

                  (newRoot, true, false)
                }
              } else {
                // no need to rotate
                val myHeightIncreased: Boolean = childHeightIncreased && r.balance == (0: Byte)
                val rBalance = if (childHeightIncreased) {
                  (r.balance - 1).toByte
                } else {
                  r.balance
                }
              
                val newR = r.changeLeft(newLeftM, rBalance, newNodes)
                assert(newR.checkHeight)
                (newR, true, myHeightIncreased)
              }

            } else {
              // no change happened
              assert(r.checkHeight)
              (r, false, false)
            }
          } else {
            // next step is to the right
            proofStream += false
            val (newRightM, changeHappened, childHeightIncreased) = modifyHelper(r.right, found)

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              // newRightM should be new, because change happened
              // That's how we know we can make changes to newRightM
              assert(newRightM.isNew)
              if (childHeightIncreased && r.balance > 0) {
                // need to rotate
                // at this point we know newRightM must be an internal node and not a leaf -- because height increased
                assert (newRightM.isInstanceOf[ProverNode])
                val newRight = newRightM.asInstanceOf[ProverNode]
            
                if (newRight.balance > 0) {
                  // single rotate
                  val newR = r.changeRight(newRight.left, 0: Byte, newNodes)
                  newRight.left = newR
                  newRight.balance = 0: Byte
                  assert(newR.checkHeight)
                  assert(newRight.checkHeight)
                  (newRight, true, false)
                } else {
                  // double rotate
                  val newRootM = newRight.left
                  assert(newRootM.isInstanceOf[ProverNode])
                  val newRoot = newRootM.asInstanceOf[ProverNode]
                  assert(newRoot.isNew) // that's how we know we can change values in newRoot

                  assert(newRight.balance < 0)
                  val rBalance = newRoot.balance match {
                    case 0 =>
                      // newRoot is a newly created node right above two leaves following an insert
                      assert(r.left.isInstanceOf[Leaf] && r.right.isInstanceOf[Leaf])
                      assert(newRight.left.isInstanceOf[Leaf] && newRight.right.isInstanceOf[Leaf])
                      newRight.balance = 0: Byte
                      0: Byte
                    case -1 =>
                      newRight.balance = 1: Byte
                      0: Byte
                    case 1 =>
                      newRight.balance = 0: Byte
                      -1: Byte
                  }
                  newRoot.balance = 0: Byte

                  val newR = r.changeRight(newRoot.left, rBalance, newNodes)
                  newRoot.left = newR
                  newRight.left = newRoot.right
                  newRoot.right = newRight

                  assert(newR.checkHeight)
                  assert(newRight.checkHeight)
                  assert(newRoot.checkHeight)

                  (newRoot, true, false)
                }
              } else {
                // no need to rotate
                val myHeightIncreased: Boolean = childHeightIncreased && r.balance == (0: Byte)
                val rBalance = if (childHeightIncreased) {
                  (r.balance + 1).toByte
                } else {
                  r.balance
                }
            
                val newR = r.changeRight(newRightM, rBalance, newNodes)
                assert(newR.checkHeight)
                (newR, true, myHeightIncreased)
              }
            } else {
              // no change happened
              assert(r.checkHeight)
              (r, false, false)
            }
          }
      }
    }
    topNode = modifyHelper(topNode, foundAbove = false)._1
  }
  

  def generateProof : NewBatchProof	 = {
    val packagedTree = new scala.collection.mutable.ArrayBuffer[AVLProofElement] // TODO: BEST OPTION?

    // Possible optimizations:
    // Don't put in the key if it's in the modification stream somewhere (savings ~32 bytes per proof, except 0 for insert)
    // Don't put in the nextLeafKey if the next leaf is in the tree, or equivalently, don't put in key if previous leaf is in the tree (savings are small if number of transactions is much smaller than number of leaves, because cases of two leaves in a row will be rare)
    // Condense a sequence of internal nodes/balances (expected savings: ~30 bytes per proof for depth 20) using bit-level stuff and maybe even "changing base without losing space" by Dodis-Patrascu-Thorup STOC 2010
    // Condensed the other queue -- of directions -- into bits from bytes. Expected savings: about 20 bytes per proof
    def packTree(rNode: ProverNodes)  {
      if (!rNode.visited) {
        packagedTree += ProofNode(LabelOnlyNodeInProof)
        packagedTree += ProofEitherLabel(rNode.label)
      }
      else {
        rNode.visited = false
        rNode match {
          case r: Leaf =>
            packagedTree += ProofNode(LeafNodeInProof)
            packagedTree += ProofKey(r.key)
            packagedTree += ProofNextLeafKey(r.nextLeafKey)
            packagedTree += ProofValue(r.value)
          case r: ProverNode =>
            packTree(r.right)
            packTree(r.left)
            packagedTree += ProofNode(InternalNodeInProof)
            packagedTree += ProofBalance(r.balance)
        }
      }
    }

    packTree(oldTopNode)
    val currentProofStream = proofStream
    
    // prepare for the next time proof
    newNodes foreach (n => {n.isNew = false; n.visited = false}) // TODO: IS THIS THE BEST SYNTAX?
    proofStream = new scala.collection.mutable.ArrayBuffer[Boolean] // TODO: BEST OPTION?
    newNodes.clear
    oldTopNode = topNode
    
    NewBatchProof(packagedTree, proofStream)
  }
}

