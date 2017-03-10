package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree.{AVLKey, AVLValue}
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.{Failure, Try}

class BatchAVLVerifier[HF <: ThreadUnsafeHash](startingDigest: Array[Byte],
                                               proof: Array[Byte],
                                               override val keyLength: Int = 32,
                                               override val valueLength: Int = 8,
                                               maxNumOperations: Option[Int] = None,
                                               maxDeletes: Option[Int] = None
                                              )
                                              // Note: -1 indicates that we don't want the proof length check done
                                              (implicit hf: HF = new Blake2b256Unsafe) extends UpdateF[Array[Byte]]
  with AuthenticatedTreeOps with ToStringHelper {

  protected val labelLength = hf.DigestSize

  def digest: Option[Array[Byte]] = topNode.map(digest(_))

  private var directionsIndex = 0
  private var lastRightStep = 0
  private var replayIndex = 0


  // Decode bits as Booleans
  protected def nextDirectionIsLeft(key: AVLKey, r: InternalNode): Boolean = {
    val ret = if ((proof(directionsIndex >> 3) & (1 << (directionsIndex & 7)).toByte) != 0) {
      true
    } else {
      lastRightStep = directionsIndex
      false
    }
    directionsIndex += 1
    ret
  }

  protected def keyMatchesLeaf(key: AVLKey, r: Leaf): Boolean = {
    val c = ByteArray.compare(key, r.key).ensuring(_ >= 0)
    if (c == 0) {
      true
    } else {
      require(ByteArray.compare(key, r.nextLeafKey) < 0)
      false
    }
  }

  protected def replayComparison: Int = {
    val ret = if (replayIndex == lastRightStep) {
      0
    } else if ((proof(replayIndex >> 3) & (1 << (replayIndex & 7)).toByte) == 0 && replayIndex < lastRightStep) {
      1
    } else {
      -1
    }
    replayIndex += 1
    ret
  }

  protected def addNode(r: Leaf, key: AVLKey, v: AVLValue): InternalVerifierNode = {
    val n = r.nextLeafKey
    new InternalVerifierNode(r.getNew(newNextLeafKey = key), new VerifierLeaf(key, v, n), 0: Byte)
  }

  protected var rootNodeHeight = 0

  private def reconstructTree: Option[VerifierNodes] = Try {

    require(labelLength > 0)
    require(keyLength > 0)
    require(valueLength >= 0)
    require(startingDigest.length == labelLength + 1)
    rootNodeHeight = startingDigest.last & 0xff

    // compute log (number of operations), rounded up
    var logNumOps = 0
    var temp = 1
    val realNumOperations: Int = maxNumOperations.getOrElse(0)
    while (temp < realNumOperations) {
      temp = temp * 2
      logNumOps += 1
    }

    // compute maximum height that the tree can be before an operation
    temp = 1 + math.max(rootNodeHeight, logNumOps)
    val hnew = temp + temp / 2 // this will replace 1.4405 with 1.5 and will round down, which is safe, because hnew is an integer
    val realMaxDeletes: Int = maxDeletes.getOrElse(realNumOperations)
    // Note: this is quite likely a lot more than there will really be nodes
    val maxNodes = (realNumOperations + realMaxDeletes) * (2 * rootNodeHeight + 1) + realMaxDeletes * hnew + 1 // +1 needed in case numOperations == 0

    var numNodes = 0
    val s = new mutable.Stack[VerifierNodes] // Nodes and depths
    var i = 0
    var previousLeaf: Option[Leaf] = None
    while (proof(i) != EndOfTreeInPackagedProof) {
      val n = proof(i)
      i += 1
      numNodes += 1
      require(maxNumOperations.isEmpty || numNodes <= maxNodes, "Proof too long")
      n match {
        case LabelInPackagedProof =>
          val label = proof.slice(i, i + labelLength)
          i += labelLength
          s.push(new LabelOnlyNode(label))
          previousLeaf = None
        case LeafInPackagedProof =>
          val key = if (previousLeaf.nonEmpty) {
            previousLeaf.get.nextLeafKey
          }
          else {
            val start = i
            i += keyLength
            proof.slice(start, i)
          }
          val nextLeafKey = proof.slice(i, i + keyLength)
          i += keyLength
          val value = proof.slice(i, i + valueLength)
          i += valueLength
          val leaf = new VerifierLeaf(key, value, nextLeafKey)
          s.push(leaf)
          previousLeaf = Some(leaf)
        case _ =>
          val right = s.pop
          val left = s.pop
          s.push(new InternalVerifierNode(left, right, n))
      }
    }

    require(s.size == 1)
    val root = s.pop
    require(startingDigest startsWith root.label)
    directionsIndex = (i + 1) * 8 // Directions start right after the packed tree, which we just finished
    Some(root)
  }.recoverWith { case e =>
    e.printStackTrace()
    Failure(e)
  }.getOrElse(None)

  private var topNode: Option[VerifierNodes] = reconstructTree

  def performOneModification(m: Modification): Unit = {
    val converted = Modification.convert(m)
    performOneModification(converted._1, converted._2)
  }

  def performOneModification(key: AVLKey, updateFunction: UpdateFunction): Unit = {
    replayIndex = directionsIndex
    topNode = Try(Some(returnResultOfOneModification(key, updateFunction, topNode.get).asInstanceOf[VerifierNodes])).getOrElse(None)
    // If TopNode was already None, then the line above should fail and return None
  }

  override def toString: String = {

    def stringTreeHelper(rNode: VerifierNodes, depth: Int): String =
      Seq.fill(depth + 2)(" ").mkString + (rNode match {
        case leaf: VerifierLeaf =>
          "At leaf label = " + arrayToString(leaf.label) + " key = " + arrayToString(leaf.key) +
            " nextLeafKey = " + arrayToString(leaf.nextLeafKey) + "\n"
        case r: InternalVerifierNode =>
          "Internal node label = " + arrayToString(r.label) + " balance = " +
            r.balance + "\n" + stringTreeHelper(r.left.asInstanceOf[VerifierNodes], depth + 1) +
            stringTreeHelper(r.right.asInstanceOf[VerifierNodes], depth + 1)
        case n: LabelOnlyNode =>
          "Label-only node label = " + arrayToString(n.label) + "\n"
      })

    topNode match {
      case None => "None"
      case Some(t) => stringTreeHelper(t, 0)
    }
  }
}