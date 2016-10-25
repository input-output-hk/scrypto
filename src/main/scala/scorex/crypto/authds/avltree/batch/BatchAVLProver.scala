package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree._
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray
import scala.collection.mutable

import scala.util.{Failure, Success}


// TODO: interfaces/inheritance/signatures

trait BatchProofConstants {
  // Do not use bytes -1, 0, or 1 -- these are for balance
  val LeafWithKeyInPackagedProof: Byte = 2
  val LeafWithoutKeyInPackagedProof: Byte = 3
  val LabelInPackagedProof: Byte = 4
  val EndOfTreeInPackagedProof: Byte = 5
}

/**
  *
  * @param rootOpt - option root hash of lold tree. Should contain new nodes only
  * @param keyLength - length of keys in tree
  * @param valueLength - length of values in tree
  * @param hf - hash function
  */
class BatchAVLProver[HF <: ThreadUnsafeHash](rootOpt: Option[Leaf] = None, keyLength: Int = 32,
                                             valueLength: Int = 8)(implicit hf: HF = new Blake2b256Unsafe)
  extends UpdateF[Array[Byte]] with BatchProofConstants {

  val labelLength = hf.DigestSize


  private val PositiveInfinityKey: Array[Byte] = Array.fill(keyLength)(-1: Byte)
  private val NegativeInfinityKey: Array[Byte] = Array.fill(keyLength)(0: Byte)


  private var topNode: ProverNodes = rootOpt.getOrElse(Leaf(NegativeInfinityKey,
    Array.fill(valueLength)(0: Byte), PositiveInfinityKey))

  topNode.isNew = false
  private var oldTopNode = topNode
  private val newNodes = new mutable.ListBuffer[ProverNodes]

  // Directions are just a bit string representing booleans
  private var directions = new mutable.ArrayBuffer[Byte]
  private var directionsBitLength: Int = 0

  private def addToDirections(d: Boolean) = {
    // encode Booleans as bits 
    if ((directionsBitLength & 7) == 0) {
      // new byte needed
      directions += (d match {
        case true => 1: Byte
        case false => 0: Byte
      })
    } else {
      val i = directionsBitLength >> 3
      if (d) directions(i) = (directions(i) | (1 << (directionsBitLength & 7))).toByte // change last byte
    }
    directionsBitLength += 1
  }

  def rootHash: Label = topNode.label


  def performOneModification(key: AVLKey, updateFunction: UpdateFunction) = {
    require(ByteArray.compare(key, NegativeInfinityKey) > 0, s"Key ${Base58.encode(key)} is less than -inf")
    require(ByteArray.compare(key, PositiveInfinityKey) < 0, s"Key ${Base58.encode(key)} is more than +inf")
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
                require(v.length == valueLength)
                val rNew = r.changeValue(v, newNodes)
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
                require(v.length == valueLength)
                val newLeaf = new Leaf(key, v, r.nextLeafKey)
                newNodes += newLeaf
                val oldLeaf = r.changeNextKey(key, newNodes)
                val newProverNode = new ProverNode(key, oldLeaf, newLeaf, 0: Byte)
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
            addToDirections(true)

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
                      assert(newRoot.left.isInstanceOf[Leaf] && newRoot.right.isInstanceOf[Leaf])
                      assert(newLeft.left.isInstanceOf[Leaf] && r.right.isInstanceOf[Leaf])
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
            addToDirections(false)
            val (newRightM, changeHappened, childHeightIncreased) = modifyHelper(r.right, found)

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              // newRightM should be new, because change happened
              // That's how we know we can make changes to newRightM
              assert(newRightM.isNew)
              if (childHeightIncreased && r.balance > 0) {
                // need to rotate
                // at this point we know newRightM must be an internal node and not a leaf -- because height increased
                assert(newRightM.isInstanceOf[ProverNode])
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
                      assert(newRoot.left.isInstanceOf[Leaf] && newRoot.right.isInstanceOf[Leaf])
                      assert(newRight.right.isInstanceOf[Leaf] && r.left.isInstanceOf[Leaf])
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


  def generateProof: Seq[Byte] = {
    val packagedTree = new mutable.ArrayBuffer[Byte]

    /* TODO Possible optimizations:
     * - Don't put in the key if it's in the modification stream somewhere 
     *   (savings ~32 bytes per proof, except 0 for insert)
     *   (problem is that then verifier logic has to change -- 
     *   can't verify tree immediately)
     * - Don't put in the nextLeafKey if the next leaf is in the tree, 
     *   or equivalently, don't put in key if previous leaf is in the tree 
     *   (savings are small if number of transactions is much smaller than  
     *   number of leaves, because cases of two leaves in a row will be rare)
     * - Condense a sequence of balances and other non-full-byte info using 
     *   bit-level stuff and maybe even "changing base without losing space" 
     *   by Dodis-Patrascu-Thorup STOC 2010 (expected savings: 5-15 bytes 
     *   per proof for depth 20) 
     */
    def packTree(rNode: ProverNodes) {
      // Post order traversal to pack up the tree
      if (!rNode.visited) {
        packagedTree += LabelInPackagedProof
        packagedTree ++= rNode.label
        assert(rNode.label.length == labelLength)
      }
      else {
        rNode.visited = false
        rNode match {
          case r: Leaf =>
            packagedTree += LeafWithKeyInPackagedProof
            packagedTree ++= r.key
            packagedTree ++= r.nextLeafKey
            packagedTree ++= r.value
          case r: ProverNode =>
            packTree(r.right)
            packTree(r.left)
            packagedTree += r.balance
        }
      }
    }

    packTree(oldTopNode)
    packagedTree += EndOfTreeInPackagedProof
    packagedTree ++= directions

    // prepare for the next time proof
    newNodes foreach (n => {
      n.isNew = false
      n.visited = false
    }) // TODO: IS THIS THE BEST SYNTAX?
    directions = new mutable.ArrayBuffer[Byte]
    directionsBitLength = 0
    newNodes.clear
    oldTopNode = topNode

    packagedTree
  }

  // TODO: write a test that examines the entire tree after a proof is produced, and checks that the isNew and visited flags are all false. It will be a very slow test, so can be invoked only when debugging

  // TODO: add a simple non-modifying non-proof-generating lookup -- a prover may simple need to know a value associated with a key, just to check a balance, for example. It should be relatively easy to take the code above and simple remove everything extra, to get a very short piece of code
}

