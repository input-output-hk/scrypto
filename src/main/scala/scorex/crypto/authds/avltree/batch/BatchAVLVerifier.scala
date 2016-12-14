package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.UpdateF
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.Try

// TODO: should this be "case"?
case class BatchAVLVerifier[HF <: ThreadUnsafeHash](startingDigest: Label, pf: Array[Byte], keyLength: Int = 32, valueLength: Int = 8)
                                                   (implicit hf: HF = new Blake2b256Unsafe) extends UpdateF[Array[Byte]] with AuthenticatedTreeOps /*TODO: need this? TwoPartyProof[AVLKey, AVLValue]*/ {

  protected val labelLength = hf.DigestSize // TODO: we shouldn't pass labelLength in, but should get it from the digest

  def digest: Option[Label] = topNode.map(_.label)

  private var directionsIndex = 0
  private var lastRightStep = 0
  private var replayIndex = 0


  // Decode bits as Booleans
  protected def nextDirectionIsLeft(key: AVLKey, r: InternalNode): Boolean = {
    val ret = if ((pf(directionsIndex >> 3) & (1 << (directionsIndex & 7)).toByte) != 0)
      true
    else {
      lastRightStep = directionsIndex
      false
    }
    directionsIndex += 1
    ret
  }

  protected def keyMatchesLeaf(key: AVLKey, r: Leaf): Boolean = {
    val c = ByteArray.compare(key, r.key)
    if (c == 0) {
      true
    }
    else {
      require(c > 0)
      require(ByteArray.compare(key, r.nextLeafKey) < 0)
      false
    }
  }

  protected def replayComparison: Int = {
    val ret = if (replayIndex == lastRightStep)
      0
    else if ((pf(replayIndex >> 3) & (1 << (replayIndex & 7)).toByte) == 0 && replayIndex < lastRightStep)
      1
    else
      -1
    replayIndex += 1
    ret
  }

  protected def addNode(r: Leaf, key: AVLKey, v: AVLValue): InternalVerifierNode = {
    val n = r.nextLeafKey
    new InternalVerifierNode(r.getNew(newNextLeafKey = key), new VerifierLeaf(key, v, n), 0: Byte)
  }

  private def reconstructTree: Option[VerifierNodes] = Try {
    val s = new mutable.Stack[VerifierNodes]
    var i = 0
    while (pf(i) != EndOfTreeInPackagedProof) {
      val n = pf(i)
      i += 1
      n match {
        case LabelInPackagedProof =>
          val label = pf.slice(i, i + labelLength)
          i += labelLength
          s.push(new LabelOnlyNode(label))
        case LeafWithKeyInPackagedProof =>
          val key = pf.slice(i, i + keyLength)
          i += keyLength
          val nextLeafKey = pf.slice(i, i + keyLength)
          i += keyLength
          val value = pf.slice(i, i + valueLength)
          i += valueLength
          s.push(new VerifierLeaf(key, value, nextLeafKey))
        case _ =>
          val left = s.pop
          val right = s.pop
          s.push(new InternalVerifierNode(left, right, n))
      }
    }
    require(s.size == 1)
    val root = s.pop.ensuring(_.label sameElements startingDigest)
    directionsIndex = (i + 1) * 8 // Directions start right after the packed tree, which we just finished
    Some(root)
  }.getOrElse(None)

  private var topNode: Option[VerifierNodes] = reconstructTree

  // TODO: SCALA QUESTION: should we copy the rest of pf into a class variable because 
  // it's mutable and so can change on us while we use it? 
  // Will there ever be a case when someone else mutates it? And also, if we copy it into the class, will we free up
  // the space that's taken up by the tree portion of the proof (which is most of the proof) --- will it get garbage collected?


  def verifyOneModification(m: Modification): Option[Label] = {
    val converted = Modification.convert(m)
    verifyOneModification(converted._1, converted._2)
  }

  def verifyOneModification(key: AVLKey, updateFunction: UpdateFunction): Option[Label] = {
    replayIndex = directionsIndex
    topNode = Try(Some(returnResultOfOneModification(key, updateFunction, topNode.get).asInstanceOf[VerifierNodes])).getOrElse(None)
    // If TopNode was already None, then the line above should fail and return None
    topNode.map(_.label)
  }

}