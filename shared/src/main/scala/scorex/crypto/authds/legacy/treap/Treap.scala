package scorex.crypto.authds.legacy.treap

import scorex.crypto.authds._
import scorex.crypto.authds.avltree.batch.{Lookup, Modification, Operation}
import scorex.crypto.authds.legacy.treap.Constants._
import scorex.crypto.hash._
import scorex.utils.ByteArray

import scala.util.{Failure, Success, Try}

/**
  * Authenticated data structure, representing both treap and binary tree, depending on level selection function
  */
//todo: make explicit skiplist interface
class Treap[HF <: CryptographicHash[_ <: Digest]](rootOpt: Option[Leaf] = None)
                                                 (implicit hf: HF = Blake2b256, lf: LevelFunction = Level.treapLevel)
  extends TwoPartyDictionary {

  var topNode: ProverNodes = rootOpt.getOrElse(Leaf(NegativeInfinity._1, NegativeInfinity._2, PositiveInfinity._1))

  def rootHash(): ADDigest = ADDigest @@@ topNode.label

  override def run[O <: Operation](operation: O): Try[TreapModifyProof] = Try {
    val key = operation.key

    require(ByteArray.compare(key, NegativeInfinity._1) > 0)
    require(ByteArray.compare(key, PositiveInfinity._1) < 0)

    //todo: unify types AVLValue/TreapValue and then generalize 4 LoCs below which are the same for Treap & AVLTree
    val updateFn: Option[ADValue] => Try[Option[ADValue]] = operation match {
      case _: Lookup => (x: Option[ADValue]) => Success(x)
      case m: Modification => m.updateFn
    }

    val proofStream = new scala.collection.mutable.Queue[WTProofElement]

    // found tells us if x has been already found above r in the tree
    // returns the new root
    // and an indicator whether tree has been modified at r or below
    def modifyHelper(rNode: ProverNodes, foundAbove: Boolean): (ProverNodes, Boolean) = {
      rNode match {
        case r: Leaf =>
          if (foundAbove) {
            // we already know it's in the tree, so it must be at the current leaf
            proofStream.enqueue(ProofDirection(LeafFound))
            proofStream.enqueue(ProofNextLeafKey(r.nextLeafKey))
            proofStream.enqueue(ProofValue(r.value))

            updateFn(Some(r.value)) match {
              case Success(None) => //delete value
                ???
              case Success(Some(v)) => //update value
                r.value = v
                (r, true)
              case Failure(e) => // found incorrect value
                throw e
            }
          } else {
            // x > r.key
            proofStream.enqueue(ProofDirection(LeafNotFound))
            proofStream.enqueue(ProofKey(r.key))
            proofStream.enqueue(ProofNextLeafKey(r.nextLeafKey))
            proofStream.enqueue(ProofValue(r.value))
            updateFn(None) match {
              case Success(None) => //don't change anything, just lookup
                ???
              case Success(Some(v)) => //insert new value
                val newLeaf = Leaf(key, v, r.nextLeafKey)
                r.nextLeafKey = key
                (ProverNode(key, r, newLeaf), true)
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
          // See if the new node needs to be swapped with r because its level > r.level (if it's left)
          // or its level >= r.level (if it's right)
          if (nextStepIsLeft) {
            proofStream.enqueue(ProofDirection(GoingLeft))
            proofStream.enqueue(ProofRightLabel(r.rightLabel))
            proofStream.enqueue(ProofLevel(r.level))

            val (newLeftM: ProverNodes, changeHappened: Boolean) = modifyHelper(r.left, found)

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
            proofStream.enqueue(ProofDirection(GoingRight))
            proofStream.enqueue(ProofLeftLabel(r.leftLabel))
            proofStream.enqueue(ProofLevel(r.level))

            val (newRightM: ProverNodes, changeHappened: Boolean) = modifyHelper(r.right, found)

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

    val (newTopNode: ProverNodes, changeHappened: Boolean) = modifyHelper(topNode, foundAbove = false)
    if (changeHappened) topNode = newTopNode
    TreapModifyProof(key, proofStream.toSeq) // .toSeq required for 2.13
  }
}
