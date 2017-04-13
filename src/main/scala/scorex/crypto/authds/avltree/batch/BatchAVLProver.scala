package scorex.crypto.authds.avltree.batch

import com.google.common.primitives.Ints
import scorex.crypto.authds.avltree.{AVLKey, AVLValue}
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.{Failure, Success, Try}


/**
  * Implements the batch AVL prover from https://eprint.iacr.org/2016/994
  *
  * @param keyLength        - length of keys in tree
  * @param valueLengthOpt      - length of values in tree. None if it is not fixed
  * @param oldRootAndHeight - option root node and height of old tree. Tree should contain new nodes only
  *                         WARNING if you pass it, all isNew and visited flags should be set correctly and height should be correct
  * @param hf               - hash function
  */
class BatchAVLProver[HF <: ThreadUnsafeHash](val keyLength: Int,
                                             val valueLengthOpt: Option[Int],
                                             oldRootAndHeight: Option[(ProverNodes, Int)] = None)
                                            (implicit val hf: HF = new Blake2b256Unsafe)
  extends AuthenticatedTreeOps with ToStringHelper {

  protected val labelLength = hf.DigestSize

  private[batch] var topNode: ProverNodes = oldRootAndHeight.map(_._1).getOrElse({
    val t = new ProverLeaf(NegativeInfinityKey,
      Array.fill(valueLengthOpt.map(_.toInt).getOrElse(0))(0: Byte), PositiveInfinityKey)
    t.isNew = false
    t
  })

  var rootNodeHeight: Int = oldRootAndHeight.map(_._2).getOrElse(0)

  private var oldTopNode = topNode

  // Directions are just a bit string representing booleans
  private var directions = new mutable.ArrayBuffer[Byte]
  private var directionsBitLength: Int = 0

  private var replayIndex = 0 // Keeps track of where we are when replaying directions
                              // a second time; needed for deletions
  private var lastRightStep = 0 // Keeps track of the last time we took a right step
                                // when going down the tree; needed for deletions
  private var found: Boolean = false // keeps track of whether the key for the current
                                     // operation has already been found in the tree
                                     // (if so, we know how to get to the leaf without
                                     //  any further comparisons)

  /**
   * Figures out whether to go left or right when from node r when searching for the key;
   * records the appropriate bit in the directions bit string to be used in the proof
   *
   * @param key
   * @param r
   * @return - true if to go left, false if to go right in the search 
   */
  protected def nextDirectionIsLeft(key: AVLKey, r: InternalNode): Boolean = {
    val ret = if (found) {
      true
    } else {
      ByteArray.compare(key, r.asInstanceOf[InternalProverNode].key) match {
        case 0 => // found in the tree -- go one step right, then left to the leaf
          found = true
          lastRightStep = directionsBitLength
          false
        case o if o < 0 => // going left
          true
        case _ => // going right
          false
      }
    }
    // encode Booleans as bits 
    if ((directionsBitLength & 7) == 0) {
      // new byte needed
      directions += (ret match {
        case true => 1: Byte
        case false => 0: Byte
      })
    } else {
      if (ret) {
        val i = directionsBitLength >> 3
        directions(i) = (directions(i) | (1 << (directionsBitLength & 7))).toByte // change last byte
      }
    }
    directionsBitLength += 1
    ret
  }

  /**
   * Determines if the leaf r contains the key
   *
   * @param key
   * @param r
   * @return 
   */
  protected def keyMatchesLeaf(key: AVLKey, r: Leaf): Boolean = {
    // The prover doesn't actually need to look at the leaf key,
    // because the prover would have already seen this key on the way
    // down the to leaf if and only if the leaf matches the key that is being sought
    val ret = found
    found = false // reset for next time
    ret
  }

  /** 
   * Deletions go down the tree twice -- once to find the leaf and realize
   * that it needs to be deleted, and the second time to actually perform the deletion.
   * This method will re-create comparison results using directions array and lastRightStep
   * variable. Each time it's called, it will give the next comparison result of 
   * key and node.key, where node starts at the root and progresses down the tree
   * according to the comparison results.
   *
   * @return - result of previous comparison of key and relevant node's key
   */
  protected def replayComparison: Int = {
    val ret = if (replayIndex == lastRightStep) {
      0
    } else if ((directions(replayIndex >> 3) & (1 << (replayIndex & 7)).toByte) == 0) {
      1
    } else {
      -1
    }
    replayIndex += 1
    ret
  }

  /**
   * @param r
   * @param key
   * @param v
   * @return - A new prover node with two leaves: r on the left and a new leaf containing key and value on the right
   */
  protected def addNode(r: Leaf, key: AVLKey, v: AVLValue): InternalProverNode = {
    val n = r.nextLeafKey
    new InternalProverNode(key, r.getNew(newNextLeafKey = key).asInstanceOf[ProverLeaf],
      new ProverLeaf(key, v, n), 0: Byte)
  }

  /**
   * Returns the current digest of the authenticated data structure,
   * which contains the root hash and the root height
   *
   * @return - the digest
   */
  def digest: Array[Byte] = digest(topNode)


  /**
   * If operation.key exists in the tree and the operation succeeds,
   * returns Success(Some(v)), where v is the value associated with operation.key
   * before the operation.
   * If operation.key exists in the tree and the operation fails, returns Success(None).
   * Returns Failure if the operation fails.
   * Does not modify the tree or the proof in case return is Failure.
   *
   * @param operation
   * @return - Success(Some(old value)), Success(None), or Failure
   */
  def performOneOperation(operation: Operation): Try[Option[AVLValue]] = Try {
    replayIndex = directionsBitLength
    returnResultOfOneOperation(operation, topNode) match {
      case Success(n) =>
        topNode = n._1.asInstanceOf[ProverNodes]
        n._2
      case Failure(e) =>
        // take the bit length before fail and divide by 8 with rounding up
        val oldDirectionsByteLength = (replayIndex + 7) / 8
        // undo the changes to the directions array
        directions.trimEnd(directions.length - oldDirectionsByteLength)
        directionsBitLength = replayIndex
        if ((directionsBitLength & 7) > 0) {
          // 0 out the bits of the last element of the directions array
          // that are above directionsBitLength
          val mask = (1 << (directionsBitLength & 7)) - 1
          directions(directions.length - 1) = (directions(directions.length - 1) & mask).toByte
        }
        throw e
    }
  }


  /**
   * Generates the proof for all the operations performed (except the ones that failed)
   * since the last generateProof call
   *
   * @return - the proof
   */
  def generateProof(): Array[Byte] = {
    val packagedTree = new mutable.ArrayBuffer[Byte]
    var previousLeafAvailable = false

    /* TODO Possible optimizations:
     * - Don't put in the key if it's in the modification stream somewhere 
     *   (savings ~32 bytes per proof for transactions with existing key; 0 for insert)
     *   (problem is that then verifier logic has to change -- 
     *   can't verify tree immediately)
     * - Condense a sequence of balances and other non-full-byte info using 
     *   bit-level stuff and maybe even "changing base without losing space" 
     *   by Dodis-Patrascu-Thorup STOC 2010 (expected savings: 5-15 bytes 
     *   per proof for depth 20, based on experiments with gzipping the array
     *   that contains only this info)
     * - Condense the sequence of values if they are mostly not randomly distributed
     * */
    def packTree(rNode: ProverNodes) {
      // Post order traversal to pack up the tree
      if (!rNode.visited) {
        packagedTree += LabelInPackagedProof
        packagedTree ++= rNode.label
        assert(rNode.label.length == labelLength)
        previousLeafAvailable = false
      } else {
        rNode.visited = false
        rNode match {
          case r: ProverLeaf =>
            packagedTree += LeafInPackagedProof
            if (!previousLeafAvailable) packagedTree ++= r.key
            packagedTree ++= r.nextLeafKey
            if(valueLengthOpt.isEmpty) {
              packagedTree ++= Ints.toByteArray(r.value.length)
            }
            packagedTree ++= r.value
            previousLeafAvailable = true
          case r: InternalProverNode =>
            packTree(r.left)
            packTree(r.right)
            packagedTree += r.balance
        }
      }
    }

    // Recursively reset the new flags
    def resetNew(r: ProverNodes): Unit = {
      if (r.isNew) {
        r match {
          case rn: InternalProverNode =>
            resetNew(rn.left)
            resetNew(rn.right)
          case _ =>
        }
        r.isNew = false
        r.visited = false
      }
    }

    packTree(oldTopNode)
    packagedTree += EndOfTreeInPackagedProof
    packagedTree ++= directions

    // prepare for the next time proof
    resetNew(topNode)
    directions = new mutable.ArrayBuffer[Byte]
    directionsBitLength = 0
    oldTopNode = topNode

    packagedTree.toArray
  }

  /**
    * A simple non-modifying non-proof-generating lookup.
    * Does not mutate the data structure
    *
    * @return Some(value) for value associated with the given key if key is in the tree, and None otherwise
    */
  def unauthenticatedLookup(key: AVLKey): Option[AVLValue] = {
    def unauthenticatedLookupHelper(rNode: ProverNodes, found: Boolean): Option[AVLValue] = {
      rNode match {
        case leaf: ProverLeaf =>
          if (found)
            Some(leaf.value)
          else
            None

        case r: InternalProverNode =>
          if (found) // left all the way to the leaf
            unauthenticatedLookupHelper(r.left, found = true)
          else {
            ByteArray.compare(key, r.key) match {
              case 0 => // found in the tree -- go one step right, then left to the leaf
                unauthenticatedLookupHelper(r.right, found = true)
              case o if o < 0 => // going left, not yet found
                unauthenticatedLookupHelper(r.left, found = false)
              case _ => // going right, not yet found
                unauthenticatedLookupHelper(r.right, found = false)
            }
          }
      }
    }
    unauthenticatedLookupHelper(topNode, found = false)
  }

  /**
    * Is for debug only
    *
    * Checks the BST order, AVL balance, correctness of leaf positions, correctness of first and last
    * leaf, correctness of nextLeafKey fields
    * If postProof, then also checks for visited and isNew fields being false
    * Warning: slow -- takes linear time in tree size
    * Throws exception if something is wrong
    **/
  private[batch] def checkTree(postProof: Boolean = false): Unit = {
    var fail: Boolean = false

    def checkTreeHelper(rNode: ProverNodes): (ProverLeaf, ProverLeaf, Int) = {
      def myRequire(t: Boolean, s: String) = {
        if (!t) {
          var x = rNode.key(0).toInt
          if (x < 0) x = x + 256
          log.error("Tree failed at key = " + x + ": " + s)
          fail = true
        }
      }

      myRequire(!postProof || (!rNode.visited && !rNode.isNew), "postproof flags")
      rNode match {
        case r: InternalProverNode =>
          if (r.left.isInstanceOf[InternalProverNode])
            myRequire(ByteArray.compare(r.left.key, r.key) < 0, "wrong left key")
          if (r.right.isInstanceOf[InternalProverNode])
            myRequire(ByteArray.compare(r.right.key, r.key) > 0, "wrong right key")

          val (minLeft, maxLeft, leftHeight) = checkTreeHelper(r.left)
          val (minRight, maxRight, rightHeight) = checkTreeHelper(r.right)
          myRequire(maxLeft.nextLeafKey sameElements minRight.key, "children don't match")
          myRequire(minRight.key sameElements r.key, "min of right subtree doesn't match")
          myRequire(r.balance >= -1 && r.balance <= 1 && r.balance.toInt == rightHeight - leftHeight, "wrong balance")
          val height = math.max(leftHeight, rightHeight) + 1
          (minLeft, maxRight, height)

        case l: ProverLeaf =>
          (l, l, 0)
      }
    }

    val (minTree, maxTree, treeHeight) = checkTreeHelper(topNode)
    require(minTree.key sameElements NegativeInfinityKey)
    require(maxTree.nextLeafKey sameElements PositiveInfinityKey)
    require(treeHeight == rootNodeHeight)

    require(!fail, "Tree failed: \n" + toString)
  }


  override def toString: String = {

    def stringTreeHelper(rNode: ProverNodes, depth: Int): String = {
      Seq.fill(depth + 2)(" ").mkString + (rNode match {
        case leaf: ProverLeaf =>
          "At leaf label = " + arrayToString(leaf.label) + " key = " + arrayToString(leaf.key) +
            " nextLeafKey = " + arrayToString(leaf.nextLeafKey) + "\n"
        case r: InternalProverNode =>
          "Internal node label = " + arrayToString(r.label) + " key = " + arrayToString(r.key) + " balance = " +
            r.balance + "\n" + stringTreeHelper(r.left, depth + 1) +
            stringTreeHelper(r.right, depth + 1)
      })
    }
    stringTreeHelper(topNode, 0)
  }
}
