package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree._
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray
import scala.util.{Failure, Success, Try}
import scorex.crypto.authds.TwoPartyDictionary.Label


// TODO: cleanup imports
// TODO: interaces/inheritance/signatures
class BatchAVLVerifier[HF <: ThreadUnsafeHash](startingDigest: Label, pf : Array[Byte], labelLength : Int = 32, keyLength : Int = 32, valueLength : Int = 8)
                         (implicit hf: HF = new Blake2b256Unsafe) extends UpdateF[Array[Byte]] with BatchProofConstants /*TwoPartyProof[AVLKey, AVLValue]*/ {

  private var directionsIndex = 0

  private def reconstructTree : Option[Node] = Try {
    val s = new scala.collection.mutable.Stack[Node] // TODO: Why can't omit "scala.collection.mutable." here if I already did import scala.collection._ above; same question in prover code
    var i = 0
    while (pf(i) != EndOfTreeInPackagedProof) {
      val n = pf(i)
      i+=1
      n match {
        case LabelInPackagedProof => 
          val label = pf.slice(i,i+labelLength).asInstanceOf[Label]
          i+=labelLength
          s.push (LabelOnlyNode(label))
        case LeafWithKeyInPackagedProof =>
          val key = pf.slice(i,i+keyLength).asInstanceOf[AVLKey]
          i+=keyLength
          val nextLeafKey = pf.slice(i,i+keyLength).asInstanceOf[AVLKey]
          i+=keyLength
          val value = pf.slice(i, i+valueLength).asInstanceOf[AVLValue]
          i+=valueLength
          s.push (Leaf(key, value, nextLeafKey))
        case _ =>
          val left = s.pop
          val right = s.pop
          s.push(VerifierNode(left, right, n))
      }
    }
    require (s.size == 1)
    val root = s.pop
    require (root.label sameElements startingDigest)
    directionsIndex = (i+1)*8 // Directions start right after the packed tree, which we just finished
    Some(root)
  }.getOrElse(None)

  private var topNode : Option[Node] = reconstructTree
  
  // TODO: SCALA QUESTION: should we copy the rest of pf into a class variable because 
  // it's mutable and so can change on us while we use it? 
  // Will there ever be a case when someone else mutates it? And also, if we copy it into the class, will we free up
  // the space that's taken up by the tree portion of the proof (which is most of the proof) --- will it get garbage collected?

  // Decode bits as Booleans
  private def getNextDirection : Boolean = {
    val ret = if ((pf(directionsIndex>>3) & (1<<(directionsIndex&7)).toByte) != 0)
      true
    else 
      false
    directionsIndex += 1
    ret
  }

  def digest : Option[Label] = topNode match { // TODO: is there a better syntax for this?
    case Some(t) => Some(t.label)
    case _ => None
  }

  
  def verifyOneModification(key: AVLKey, updateFunction: UpdateFunction): Option[Label] =  {

    /*
     * Returns the new root and indicators whether tree has been modified at r or below
     * and whether the height has increased
     */
    def verifyHelper(rNode: VerifierNodes): (VerifierNodes, Boolean, Boolean) = {
      rNode match {
        case r: Leaf =>
          val c = ByteArray.compare(r.key, key)
          if (c==0) {
            updateFunction(Some(r.value)) match {
              case Success(None) => //delete value
                ???
              case Success(Some(v)) => //update value
                r.value = v
                (r, true, false)
              case Failure(e) => // found incorrect value
                throw e
            }
          } else {
            require(c < 0)
            require(ByteArray.compare(key, r.nextLeafKey) < 0)
            updateFunction(None) match {
              case Success(None) => //don't change anything, just lookup
                (r, false, false)
              case Success(Some(v)) => //insert new value
                val newLeaf = new Leaf(key, v, r.nextLeafKey)
                r.nextLeafKey = key
                val newR = VerifierNode(r, newLeaf, 0: Byte)
                (newR, true, true)
              case Failure(e) => // found incorrect value
                // (r, false, false, oldLabel)
                throw e
            }
          }
        case r: VerifierNode =>
          val nextStepIsLeft = getNextDirection

          // Now go recursively in the direction we just figured out
          // Get a new node
          // See if a single or double rotation is needed for AVL tree balancing
          if (nextStepIsLeft) {

            val (newLeftM, changeHappened, childHeightIncreased) = verifyHelper(r.left.asInstanceOf[VerifierNodes])

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              if (childHeightIncreased && r.balance < 0) {
                // need to rotate
                // at this point we know newleftM must be an internal node and not a leaf -- because height increased
                val newLeft = newLeftM.asInstanceOf[VerifierNode]
          
                if (newLeft.balance < 0) {
                  // single rotate
                  r.left = newLeft.right
                  r.balance = 0: Byte
                  newLeft.right = r
                  newLeft.balance = 0: Byte
                  (newLeft, true, false)
                } else {
                  // double rotate
                  val newRootM = newLeft.right
                  val newRoot = newRootM.asInstanceOf[VerifierNode]

                  val rBalance = newRoot.balance match {
                    case 0 =>
                      // newRoot is a newly created node right above two leaves following an insert
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
            
                  r.left = newRoot.right
                  r.balance = rBalance
                  newRoot.right = r
                  newLeft.right = newRoot.left
                  newRoot.left = newLeft

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
            
                r.left = newLeftM
                r.balance = rBalance
                (r, true, myHeightIncreased)
              }

            } else {
              // no change happened
              (r, false, false)
            }
          } else {
            // next step is to the right
            val (newRightM, changeHappened, childHeightIncreased) = verifyHelper(r.right.asInstanceOf[VerifierNodes])

            // balance = -1 if left higher, +1 if left lower
            if (changeHappened) {
              if (childHeightIncreased && r.balance > 0) {
                // need to rotate
                // at this point we know newRightM must be an internal node and not a leaf -- because height increased
                val newRight = newRightM.asInstanceOf[VerifierNode]
          
                if (newRight.balance > 0) {
                  // single rotate
                  r.right = newRight.left
                  r.balance = 0: Byte
                  newRight.left = r
                  newRight.balance = 0: Byte
                  (newRight, true, false)
                } else {
                  // double rotate
                  val newRootM = newRight.left
                  val newRoot = newRootM.asInstanceOf[VerifierNode]

                  val rBalance = newRoot.balance match {
                    case 0 =>
                      // newRoot is a newly created node right above two leaves following an insert
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

                  r.right = newRoot.left
                  r.balance = rBalance
                  newRoot.left = r
                  newRight.left = newRoot.right
                  newRoot.right = newRight

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
          
                r.right = newRightM
                r.balance = rBalance
                (r, true, myHeightIncreased)
              }
            } else {
              // no change happened
              (r, false, false)
            }
          }
      }
    }
    
    topNode = Try(Some(verifyHelper(topNode.getOrElse(None).asInstanceOf[VerifierNodes])._1)).getOrElse(None)
    // If TopNode was already None, then the line above should fail and return None
    topNode match { // TODO: is there a better syntax for this?
      case Some(t) => Some(t.label)
      case _ => None
    }
  }
}
