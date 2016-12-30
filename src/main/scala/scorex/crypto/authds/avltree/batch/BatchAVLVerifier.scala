package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.authds.avltree.{AVLKey, AVLValue}
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray
import scala.collection.mutable
import scala.util.Try

class BatchAVLVerifier[HF <: ThreadUnsafeHash](startingDigest: Label,
                                               pf: Array[Byte],
                                               val keyLength: Int = 32,
                                               val valueLength: Int = 8,
                                               startingHeight: Int = 100,
                                               numOperations: Option[Int] = None,
                                               maxDeletes: Option[Int] = None
                                              )
                                              // Note: -1 indicates that we don't want the proof length check done
                                              (implicit hf: HF = new Blake2b256Unsafe) extends UpdateF[Array[Byte]]
  with AuthenticatedTreeOps with ToStringHelper {

  protected val labelLength = hf.DigestSize

  def digest: Option[Label] = topNode.map(_.label)

  private var directionsIndex = 0
  private var lastRightStep = 0
  private var replayIndex = 0


  // Decode bits as Booleans
  protected def nextDirectionIsLeft(key: AVLKey, r: InternalNode): Boolean = {
    val ret = if ((pf(directionsIndex >> 3) & (1 << (directionsIndex & 7)).toByte) != 0) {
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
    } else if ((pf(replayIndex >> 3) & (1 << (replayIndex & 7)).toByte) == 0 && replayIndex < lastRightStep) {
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

  private def reconstructTree: Option[VerifierNodes] = Try {

    // compute log (number of operations), rounded up
    var logNumOps = 0
    var temp = 1
    val realNumOperations: Int = numOperations.getOrElse(0)
    while (temp < realNumOperations) {
      temp = temp * 2
      logNumOps += 1
    }

    // compute maximum height that the tre can be before an operation
    temp = 1 + math.max(topNodeHeight, logNumOps)
    val hnew = temp + temp / 2 // this will replace 1.4405 with 1.5 and will round down, which is safe, because hnew is an integer
    val realMaxDeletes: Int = maxDeletes.getOrElse(realNumOperations)
    // Note: this is quite likely a lot more than there will really be nodes
    val maxNodes = (realNumOperations + realMaxDeletes) * (2 * topNodeHeight + 1) + realMaxDeletes * hnew + 1 // +1 needed in case numOperations == 0

    var numNodes = 0
    val s = new mutable.Stack[VerifierNodes] // Nodes and depths
    var i = 0
    var previousLeaf: Option[Leaf] = None
    while (pf(i) != EndOfTreeInPackagedProof) {
      val n = pf(i)
      i += 1
      numNodes += 1
      require(numOperations.isEmpty || numNodes <= maxNodes, "Proof too long")
      n match {
        case LabelInPackagedProof =>
          val label = pf.slice(i, i + labelLength)
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
            pf.slice(start, i)
          }
          val nextLeafKey = pf.slice(i, i + keyLength)
          i += keyLength
          val value = pf.slice(i, i + valueLength)
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
    val root = s.pop.ensuring(_.label sameElements startingDigest) // TODO: the use of "ensuring worries" me because it fails via "java.lang.AssertionError" rather than "scala.Predef$.require" like require fails. I am afraid assertions may be turned off, in which case verifier will fail to detect a cheating prover. Can this get turned off somehow?
    directionsIndex = (i + 1) * 8 // Directions start right after the packed tree, which we just finished
    Some(root)
  }.getOrElse(None)

  protected var topNodeHeight = startingHeight
  private var topNode: Option[VerifierNodes] = reconstructTree

  def performOneModification(m: Modification): Option[Label] = {
    val converted = Modification.convert(m)
    performOneModification(converted._1, converted._2)
  }

  def performOneModification(key: AVLKey, updateFunction: UpdateFunction): Option[Label] = {
    replayIndex = directionsIndex
    topNode = Try(Some(returnResultOfOneModification(key, updateFunction, topNode.get).asInstanceOf[VerifierNodes])).getOrElse(None)
    // If TopNode was already None, then the line above should fail and return None
    topNode.map(_.label)
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