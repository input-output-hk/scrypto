package scorex.crypto.authds.binary

import com.google.common.primitives.Ints
import scorex.crypto.hash.Sha256
import scorex.utils.ByteArray

import scala.annotation.tailrec

class SLTree(rootOpt: Option[Node] = None) {

  var rootNode: Node = rootOpt.getOrElse(Sentinel)
  def rootHash(): Label = rootNode.label

  def insert(key: SLTKey, value: SLTValue): (Boolean, SLTInsertProof) = {
    val (newRoot, isSuccess, proof) = SLTree.insert(rootNode, key, value)
    if (isSuccess) rootNode = newRoot
    (isSuccess, proof)
  }

}


object SLTree {


  def label(n: Option[NodeI]): Label = n.map(_.label).getOrElse(Array())

  /**
    *
    * @return (new root node, whether element was inserted, insertProof)
    */
  def insert(root: Node, key: SLTKey, value: SLTValue): (Node, Boolean, SLTInsertProof) = {

    val proofStream = new scala.collection.mutable.Queue[SLTProofElement]
    proofStream.enqueue(SLTProofKey(root.key))
    proofStream.enqueue(SLTProofValue(root.value))
    proofStream.enqueue(SLTProofLevel(root.level))
    proofStream.enqueue(SLTProofLeftLabel(label(root.left)))

    // The newly returned node may not have its label computed yet,
    // so it’s up to the caller to compute it if it is equal tmo labelOfNone
    // The reason is that in some cases we don’t know if it will move up,
    // and we don’t want to waste hashing until we are sure
    def InsertHelper(rOpt: Option[Node], x: SLTKey, value: SLTValue): (Node, Boolean) = {
      rOpt match {
        case None =>
          // No need to set maxLevel here -- we don’t risk anything by having a
          // a very high level, because data structure size remains the same
          val level = computeLevel(x, value)
          // Create a new node without computing its hash, because its hash will change
          val n = new Node(x, value, level, None, None, LabelOfNone)
          (n, true)
        case Some(r: Node) =>
          proofStream.enqueue(SLTProofKey(r.key))
          proofStream.enqueue(SLTProofValue(r.value))
          proofStream.enqueue(SLTProofLevel(r.level))
          ByteArray.compare(x, r.key) match {
            case 0 =>
              proofStream.enqueue(SLTProofLeftLabel(label(r.left)))
              proofStream.enqueue(SLTProofRightLabel(label(r.right)))
              (r, false)
            case o if o < 0 =>
              proofStream.enqueue(SLTProofRightLabel(label(r.right)))
              val (newLeft: Node, success: Boolean) = InsertHelper(r.left, x, value)
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
              // newRight.level<= r.level TODO newRight is not defined here
              // (because on the right level is allowed to be the same as of the child,
              // but on the left the child has to be smaller)
              proofStream.enqueue(SLTProofRightLabel(label(r.right)))
              val (newRight: Node, success: Boolean) = InsertHelper(r.left, x, value)
              if (success) {
                // Attach the newLeft if its level is smaller than our level;
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
                  r.right = newRight.right
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

    val (newRight, success) = InsertHelper(root.right, key, value)
    if (success) {
      if (newRight.label sameElements LabelOfNone) {
        newRight.label = newRight.computeLabel
      }
      // Elevate the level of the sentinel tower to the level of the newly inserted element,
      // if it’s higher
      if (newRight.level > root.level) root.level = newRight.level
      root.label = root.computeLabel
    }
    (root, success, SLTInsertProof(key, value, proofStream))
  }

  def computeLevel(key: SLTKey, value: SLTValue): Int = {
    @tailrec
    def loop(lev: Int = 0): Int = {
      if (Sha256(key ++ value ++ Ints.toByteArray(lev)).head.toInt < 0) lev
      else loop(lev + 1)
    }
    loop()
  }

}
