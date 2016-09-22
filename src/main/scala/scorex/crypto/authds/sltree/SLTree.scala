package scorex.crypto.authds.sltree

import com.google.common.primitives.Ints
import scorex.crypto.authds._
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, CryptographicHash, Sha256}
import scorex.utils.ByteArray

import scala.annotation.tailrec

class SLTree[HF <: CryptographicHash](rootOpt: Option[Node] = None)(implicit hf: HF = Blake2b256)
  extends TwoPartyDictionary[SLTKey, SLTValue] {


  override def modify(key: SLTKey, updateFunction: UpdateFunction,
                      toInsertIfNotFound: Boolean): TwoPartyProof[SLTKey, SLTValue] = {
    val lookupProof = lookup(key)
    lookupProof._1 match {
      case None if toInsertIfNotFound => insert(key, updateFunction)._2
      case Some(v) => update(key, updateFunction)._2
      case _ => lookupProof._2
    }
  }

  var topNode: Node = rootOpt.getOrElse {
    val r = new Node(Array(), Array(), IntLevel(0), None, None, LabelOfNone)
    r.label = r.computeLabel
    r
  }

  def rootHash(): Label = topNode.label

  def insert(key: SLTKey, updateFunction: UpdateFunction): (Boolean, SLTInsertProof) = {
    val root = topNode
    val proofStream = new scala.collection.mutable.Queue[SLTProofElement]
    proofStream.enqueue(ProofKey(root.key))
    proofStream.enqueue(ProofValue(root.value))
    proofStream.enqueue(ProofLevel(root.level))
    proofStream.enqueue(ProofLeftLabel(root.leftLabel))

    // The newly returned node may not have its label computed yet,
    // so it’s up to the caller to compute it if it is equal tmo labelOfNone
    // The reason is that in some cases we don’t know if it will move up,
    // and we don’t want to waste hashing until we are sure
    def InsertHelper(rOpt: Option[Node], x: SLTKey): (Node, Boolean) = {
      rOpt match {
        case None =>
          // No need to set maxLevel here -- we don’t risk anything by having a
          // a very high level, because data structure size remains the same
          val level = SLTree.computeLevel(x)
          // Create a new node without computing its hash, because its hash will change
          val n = new Node(x, updateFunction(None), level, None, None, LabelOfNone)
          (n, true)
        case Some(r: Node) =>
          proofStream.enqueue(ProofKey(r.key))
          proofStream.enqueue(ProofValue(r.value))
          proofStream.enqueue(ProofLevel(r.level))
          ByteArray.compare(x, r.key) match {
            case 0 =>
              proofStream.enqueue(ProofLeftLabel(r.leftLabel))
              proofStream.enqueue(ProofRightLabel(r.rightLabel))
              (r, false)
            case o if o < 0 =>
              proofStream.enqueue(ProofRightLabel(r.rightLabel))
              val (newLeft: Node, success: Boolean) = InsertHelper(r.left, x)
              if (success) {
                // Attach the newLeft if its level is smaller than our level;
                // compute its hash if needed,
                // because it’s not going to move up
                val newR = if (newLeft.level < r.level) {
                  if (newLeft.label sameElements LabelOfNone) {
                    newLeft.label = newLeft.computeLabel
                  }
                  r.left = Some(newLeft)
                  r.label = r.computeLabel
                  r
                } else {
                  // We need to rotate r with newLeft
                  r.left = newLeft.right
                  r.label = r.computeLabel
                  newLeft.right = Some(r)
                  newLeft
                  // don’t compute the label of newR, because it may still change
                }
                (newR, true)
              } else (r, false)
            case _ =>
              // Everything symmetric, except replace newLeft.level<r.level with
              // newRight.level<= r.level
              // (because on the right level is allowed to be the same as of the child,
              // but on the left the child has to be smaller)
              proofStream.enqueue(ProofLeftLabel(r.leftLabel))
              val (newRight: Node, success: Boolean) = InsertHelper(r.right, x)
              if (success) {
                // Attach the newRight if its level is smaller than our level;
                // compute its hash if needed,
                // because it’s not going to move up
                val newR = if (newRight.level <= r.level) {
                  if (newRight.label sameElements LabelOfNone) {
                    newRight.label = newRight.computeLabel
                  }
                  r.right = Some(newRight)
                  r.label = r.computeLabel
                  r
                } else {
                  // We need to rotate r with newLeft
                  r.right = newRight.left
                  r.label = r.computeLabel
                  newRight.left = Some(r)
                  newRight
                  // don’t compute the label of newR, because it may still change
                }
                (newR, true)
              } else (r, false)
          }
      }
    }

    val (newRight, success) = InsertHelper(root.right, key)
    if (success) {
      if (newRight.label sameElements LabelOfNone) {
        newRight.label = newRight.computeLabel
      }
      root.right = Some(newRight)
      // Elevate the level of the sentinel tower to the level of the newly inserted element,
      // if it’s higher
      if (newRight.level > root.level) root.level = newRight.level
      root.label = root.computeLabel
      topNode = root
    }

    (success, SLTInsertProof(key, proofStream))
  }

  def update(key: SLTKey, updateFunction: UpdateFunction): (Boolean, SLTUpdateProof) = {
    val proofStream = new scala.collection.mutable.Queue[SLTProofElement]
    def updateLoop(r: Node): Boolean = {
      proofStream.enqueue(ProofKey(r.key))
      proofStream.enqueue(ProofValue(r.value))
      proofStream.enqueue(ProofLevel(r.level))

      var found = false
      ByteArray.compare(key, r.key) match {
        case 0 =>
          proofStream.enqueue(ProofLeftLabel(r.leftLabel))
          proofStream.enqueue(ProofRightLabel(r.rightLabel))
          val newVal = updateFunction(Some(r.value))
          r.value = newVal
          found = true
        case o if o < 0 =>
          proofStream.enqueue(ProofRightLabel(r.rightLabel))
          r.left match {
            case None => found = false
            case Some(leftNode) => found = updateLoop(leftNode)
          }
        case _ =>
          proofStream.enqueue(ProofLeftLabel(r.leftLabel))
          r.right match {
            case None => found = false
            case Some(rightNode) => found = updateLoop(rightNode)
          }
      }
      if (found) r.label = r.computeLabel
      found
    }
    (updateLoop(topNode), SLTUpdateProof(key, proofStream))
  }

  def modify(key: SLTKey, updateFunction: UpdateFunction): (Boolean, SLTModifyingProof) = {
    lookup(key)._1 match {
      case Some(_) => update(key, updateFunction)
      case None => insert(key, updateFunction)
    }
  }

  def lookup(key: SLTKey): (Option[SLTValue], SLTLookupProof) = {
    val proofStream = new scala.collection.mutable.Queue[SLTProofElement]
    @tailrec
    def lookupLoop(r: Node, x: SLTKey): Option[SLTValue] = {
      proofStream.enqueue(ProofKey(r.key))
      proofStream.enqueue(ProofValue(r.value))
      proofStream.enqueue(ProofLevel(r.level))
      ByteArray.compare(x, r.key) match {
        case 0 =>
          proofStream.enqueue(ProofLeftLabel(r.leftLabel))
          proofStream.enqueue(ProofRightLabel(r.rightLabel))
          Some(r.value)
        case o if o < 0 =>
          proofStream.enqueue(ProofRightLabel(r.rightLabel))
          r.left match {
            case None => None
            case Some(leftNode) => lookupLoop(leftNode, x)
          }
        case _ =>
          proofStream.enqueue(ProofLeftLabel(r.leftLabel))
          r.right match {
            case None => None
            case Some(rightNode) => lookupLoop(rightNode, x)
          }
      }
    }
    (lookupLoop(topNode, key), SLTLookupProof(key, proofStream))
  }

  override def toString: String = {
    def mk(n: Node): String = {
      n.toString
      val ln = n.left.map(n => mk(n)).getOrElse("")
      val rn = n.right.map(n => mk(n)).getOrElse("")
      n.toString + "\n" + rn + ln
    }
    s"SLTree(${Base58.encode(rootHash()).take(8)}}): \n${mk(topNode)}"
  }

}

object SLTree {
  def computeLevel(key: SLTKey): Level = {
    @tailrec
    def loop(lev: Int = 0): Int = {
      if (Sha256(key ++ Ints.toByteArray(lev)).head.toInt < 0) lev
      else loop(lev + 1)
    }
    IntLevel(loop())
  }

}