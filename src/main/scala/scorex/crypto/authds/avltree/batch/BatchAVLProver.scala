package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.Try


/**
  *
  * @param o           - option root node of old tree. Tree should contain new nodes only
  * @param keyLength   - length of keys in tree
  * @param valueLength - length of values in tree
  * @param hf          - hash function
  */
class BatchAVLProver[HF <: ThreadUnsafeHash](o: Option[ProverNodes] = None /*TODO: THIS ARGUMENT IS NOT USED*/ ,
                                             val keyLength: Int = 32,
                                             val valueLength: Int = 8)(implicit val hf: HF = new Blake2b256Unsafe)
  extends UpdateF[Array[Byte]] with AuthenticatedTreeOps {

  protected val labelLength = hf.DigestSize

  private[batch] var topNode: ProverNodes = new ProverLeaf(NegativeInfinityKey,
    Array.fill(valueLength)(0: Byte), PositiveInfinityKey)
  topNode.isNew = false

  private var oldTopNode = topNode

  // Directions are just a bit string representing booleans
  private var directions = new mutable.ArrayBuffer[Byte]
  private var directionsBitLength: Int = 0

  private var replayIndex = 0
  private var lastRightStep = 0
  private var found: Boolean = false

  protected def nextDirectionIsLeft(key: AVLKey, r: InternalNode): Boolean = {
    val ret = if (found)
      true
    else {
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

  protected def keyMatchesLeaf(key: AVLKey, r: Leaf): Boolean = {
    val ret = found
    found = false // reset for next time
    ret
  }

  protected def replayComparison: Int = {
    val ret = if (replayIndex == lastRightStep)
      0
    else if ((directions(replayIndex >> 3) & (1 << (replayIndex & 7)).toByte) == 0)
      1
    else
      -1
    replayIndex += 1
    ret
  }

  protected def addNode(r: Leaf, key: AVLKey, v: AVLValue): InternalProverNode = {
    val n = r.nextLeafKey
    new InternalProverNode(key, r.getNew(newNextLeafKey = key), new ProverLeaf(key, v, n), 0: Byte)
  }


  def rootHash: Label = topNode.label

  def performOneModification(m: Modification): Try[Unit] = {
    val converted = Modification.convert(m)
    performOneModification(converted._1, converted._2)
  }

  def performOneModification(key: AVLKey, updateFunction: UpdateFunction): Try[Unit] = Try {
    replayIndex = directionsBitLength
    topNode = returnResultOfOneModification(key, updateFunction, topNode).asInstanceOf[ProverNodes]
  }


  def generateProof: Seq[Byte] = {
    val packagedTree = new mutable.ArrayBuffer[Byte]

    /* TODO Possible optimizations:
     * - Don't put in the key if it's in the modification stream somewhere 
     *   (savings ~32 bytes per proof for transactions with existing key; 0 for insert)
     *   (problem is that then verifier logic has to change -- 
     *   can't verify tree immediately)
     * - Don't put in the nextLeafKey if the next leaf is in the tree, 
     *   or equivalently, don't put in key if previous leaf is in the tree 
     *   (savings are small if number of transactions is much smaller than  
     *   number of leaves, because cases of two leaves in a row will be rare)
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
      } else {
        rNode.visited = false
        rNode match {
          case r: ProverLeaf =>
            packagedTree += LeafWithKeyInPackagedProof
            packagedTree ++= r.key
            packagedTree ++= r.nextLeafKey
            packagedTree ++= r.value
          case r: InternalProverNode =>
            packTree(r.right.asInstanceOf[ProverNodes])
            packTree(r.left.asInstanceOf[ProverNodes])
            packagedTree += r.balance
        }
      }
    }

    def resetNew(r: ProverNodes): Unit = {
      if (r.isNew) {
        if (r.isInstanceOf[InternalProverNode]) {
          val rn = r.asInstanceOf[InternalProverNode]
          resetNew(rn.left.asInstanceOf[ProverNodes])
          resetNew(rn.right.asInstanceOf[ProverNodes])
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

    packagedTree
  }

  /* a simple non-modifying non-proof-generating lookup
   * returns Some[value] for this key if key is in the tree, and None otherwise
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
            unauthenticatedLookupHelper(r.left.asInstanceOf[ProverNodes], true)
          else {
            ByteArray.compare(key, r.key) match {
              case 0 => // found in the tree -- go one step right, then left to the leaf
                unauthenticatedLookupHelper(r.right.asInstanceOf[ProverNodes], true)
              case o if o < 0 => // going left, not yet found
                unauthenticatedLookupHelper(r.left.asInstanceOf[ProverNodes], false)
              case _ => // going right, not yet found
                unauthenticatedLookupHelper(r.right.asInstanceOf[ProverNodes], false)
            }
          }
      }
    }
    unauthenticatedLookupHelper(topNode, false)
  }


  /* TODO: below is for debug only */

  /* Checks the BST order, AVL balance, correctness of leaf positions, correctness of first and last
   * leaf, correctness of nextLeafKey fields
   * If postProof, then also checks for visited and isNew fields being false
   * Warning: slow -- takes linear time in tree size
   * */
  def checkTree(postProof: Boolean = false): Unit = {
    var fail: Boolean = false

    def checkTreeHelper(rNode: ProverNodes): (ProverLeaf, ProverLeaf, Int) = {
      def assert1(t: Boolean, s: String) = {
        if (!t) {
          print("Tree failed at key = ")
          var x = rNode.key(0).toInt
          if (x < 0) x = x + 256
          print(x);
          print(": ")
          println(s)
          fail = true
        }
      }

      assert1(!postProof || (!rNode.visited && !rNode.isNew), "postproof flags")
      rNode match {
        case r: InternalProverNode =>
          if (r.left.isInstanceOf[InternalProverNode])
            assert1(ByteArray.compare(r.left.asInstanceOf[ProverNodes].key, r.key) < 0, "wrong left key")
          if (r.right.isInstanceOf[InternalProverNode])
            assert1(ByteArray.compare(r.right.asInstanceOf[ProverNodes].key, r.key) > 0, "wrong right key")

          val (minLeft, maxLeft, leftHeight) = checkTreeHelper(r.left.asInstanceOf[ProverNodes])
          val (minRight, maxRight, rightHeight) = checkTreeHelper(r.right.asInstanceOf[ProverNodes])
          assert1(maxLeft.nextLeafKey == minRight.key, "children don't match")
          assert1(minRight.key == r.key, "min of right subtree doesn't match")
          assert1(r.balance >= -1 && r.balance <= 1 && r.balance == rightHeight - leftHeight, "wrong balance")
          val height = math.max(leftHeight, rightHeight) + 1
          assert1(height == r.height, "height doesn't match")
          (minLeft, maxRight, height)

        case l: ProverLeaf =>
          (l, l, 0)
      }
    }


    val (minTree, maxTree, treeHeight) = checkTreeHelper(topNode)
    assert(minTree.key == NegativeInfinityKey)
    assert(maxTree.nextLeafKey == PositiveInfinityKey)
    if (fail) {
      printTree
      assert(false)
    }
  }


  def printTree = {
    println
    def printByteArray(a: Array[Byte]) = {
      var x: Int = a(0)
      if (x < 0) x = 256 + x
      print(x)
    }
    def printTreeHelper(rNode: ProverNodes, depth: Int): Unit = {
      for (i <- 0 until depth + 2)
        print(" ")
      rNode match {
        case leaf: ProverLeaf =>
          print("At leaf label = ")
          printByteArray(leaf.label)
          print(" key = ")
          printByteArray(leaf.key)
          print(" nextLeafKey = ")
          printByteArray(leaf.nextLeafKey)
          println
        case r: InternalProverNode =>
          print("Internal node label = ")
          printByteArray(r.label)
          print(" key = ")
          printByteArray(r.key)
          print(" balance = ")
          print(r.balance)
          print(" height = ")
          println(r.height)
          printTreeHelper(r.left.asInstanceOf[ProverNodes], depth + 1)
          printTreeHelper(r.right.asInstanceOf[ProverNodes], depth + 1)
      }
    }
    printTreeHelper(topNode, 0)
  }


}
