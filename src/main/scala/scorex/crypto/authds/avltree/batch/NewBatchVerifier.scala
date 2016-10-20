package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree._
import scorex.utils.Random

import com.google.common.primitives.Bytes
import scorex.crypto.authds._
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray
import scorex.crypto.encode.Base58

import scala.collection._
import scala.util.{Failure, Success, Try}
import scorex.crypto.authds.TwoPartyDictionary.Label



// TODO: interaces/inheritance/signatures
class NewBatchVerifier[HF <: ThreadUnsafeHash](startingDigest: Label, pf : NewBatchProof)
                         (implicit hf: HF = new Blake2b256Unsafe) extends UpdateF[Array[Byte]] /*TwoPartyProof[AVLKey, AVLValue]*/ {

  private def reconstructTree (seq: Seq[AVLProofElement]) : Option[Node] = Try {
    val s = new scala.collection.mutable.Stack[Node] // TODO: Why can't omit "scala.collection.mutable." here if I already did import scala.collection._ above; same question in verifier code
    var i = 0 //TODO: change to an iterator
    while (i<seq.length) {
      val l : Byte = seq(i).bytes(0)
      i += 1
      l match {
        case 2 => // TODO: should we just leave it as -1,0,1,2,3?
          val label = seq(i).asInstanceOf[ProofEitherLabel].e
          s.push (LabelOnlyNode(label))
          i+=1
        case 3 =>
          val key = seq(i).asInstanceOf[ProofKey].e
          i+=1
          val nextLeafKey = seq(i).asInstanceOf[ProofNextLeafKey].e
          i+=1
          val value = seq(i).asInstanceOf[ProofValue].e
          i+=1
          s.push (Leaf(key, value, nextLeafKey))
        case _ =>
          val left = s.pop
          val right = s.pop
          s.push(VerifierNode(left, right, l))
      }
    }
    require (s.size == 1)
    val root = s.pop
    require (root.label sameElements startingDigest)
    Some(root)
  }.getOrElse(None)

  private var topNode = reconstructTree(pf.packedTree) // TODO: SCALA QUESTION: packedTree is no longer needed after init; how do we free up this memory if it's no needed elsewere?
  // TODO: SCALA QUESTION: should we copy pf.directions over here because it's mutable and so can change on us while we use it? Will there ever be a case when someone else mutates it?
  private var proofSeqIndex = 0

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
          val nextStepIsLeft = pf.directions(proofSeqIndex) // TODO: MAKE AN INTERATOR
          proofSeqIndex+=1

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
