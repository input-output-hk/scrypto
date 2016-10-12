package scorex.crypto.authds.avltree

import com.google.common.primitives.Bytes
import scorex.crypto.authds._
import scorex.crypto.hash.{Blake2b256Unsafe, ThreadUnsafeHash}
import scorex.utils.ByteArray

import scala.collection.mutable
import scala.util.{Success, Try}


case class AVLModifyProof(key: AVLKey, proofSeq: Seq[AVLProofElement])
                         (implicit hf: ThreadUnsafeHash) extends TwoPartyProof[AVLKey, AVLValue] {

  val keyFound = proofSeq.length % 3 == 0

  /**
    * seqLength, key, ++
    * notFound: Seq(ProofDirection, ProofLabel, ProofBalance), ProofDirection, ProofKey, ProofNextLeafKey, ProofValue
    * found: Seq(ProofDirection, ProofLabel, ProofBalance), ProofDirection, ProofNextLeafKey, ProofValue
    */
  lazy val bytes: Array[Byte] = {

    val pathLength = if(keyFound) proofSeq.length - 3 else proofSeq.length - 4
    val inBytes = pathLength.toByte +: key
    val pathProofsBytes: Array[Byte] = (0 until pathLength / 3).toArray.flatMap { i: Int =>
      val label = proofSeq(3 * i + 1)
      val directionLabelByte = AVLModifyProof.directionBalanceByte(proofSeq(3 * i).asInstanceOf[ProofDirection],
        proofSeq(3 * i + 2).asInstanceOf[ProofBalance])

      Bytes.concat(Array(directionLabelByte), label.bytes)
    }
    if (keyFound) {
      Bytes.concat(inBytes, pathProofsBytes,
        Array(AVLModifyProof.combineBytes(1: Byte, proofSeq(proofSeq.length - 3).bytes.head)),
        proofSeq(proofSeq.length - 2).bytes, proofSeq.last.bytes)
    } else {
      Bytes.concat(inBytes, pathProofsBytes,
        Array(AVLModifyProof.combineBytes(0: Byte, proofSeq(proofSeq.length - 4).bytes.head)),
        proofSeq(proofSeq.length - 2).bytes, proofSeq(proofSeq.length - 3).bytes, proofSeq.last.bytes)
    }
  }

  def verifyLookup(digest: Label, existence: Boolean): Option[Label] = Try {
    val foundKey = proofSeq(proofSeq.length - 3).asInstanceOf[ProofKey].e
    val nextLeafKey = proofSeq(proofSeq.length - 2).asInstanceOf[ProofNextLeafKey].e
    val nonEx = ByteArray.compare(foundKey, key) < 0 && ByteArray.compare(nextLeafKey, key) > 0
    val e = verify(digest, TwoPartyDictionary.lookupFunction[AVLValue])
    if ((existence && (key sameElements foundKey)) || (!existence && nonEx)) {
      verify(digest, TwoPartyDictionary.lookupFunction[AVLValue])
    } else None

  }.getOrElse(None)

  def verify(digest: Label, updateFunction: UpdateFunction): Option[Label] = Try {
    val proof: mutable.Queue[TwoPartyProofElement] = mutable.Queue(proofSeq: _*)

    /*
     * Returns the new flat root and an indicator whether tree has been modified at r or below
     * Also returns the label of the old root
     */
    def verifyHelper(): (VerifierNodes, Boolean, Boolean, Label) = {
      dequeueDirection(proof) match {
        case LeafFound =>
          val nextLeafKey: AVLKey = dequeueNextLeafKey(proof)
          val value: AVLValue = dequeueValue(proof)
          val oldLeaf = Leaf(key, value, nextLeafKey)
          val newLeaf = Leaf(key, updateFunction(Some(value)).get, nextLeafKey)
          (newLeaf, true, false, oldLeaf.label)
        case LeafNotFound =>
          val neighbourLeafKey = dequeueKey(proof)
          val nextLeafKey: AVLKey = dequeueNextLeafKey(proof)
          val value: AVLValue = dequeueValue(proof)
          require(ByteArray.compare(neighbourLeafKey, key) < 0)
          require(ByteArray.compare(key, nextLeafKey) < 0)

          val r = new Leaf(neighbourLeafKey, value, nextLeafKey)
          val oldLabel = r.label
          updateFunction(None) match {
            case Success(v) =>
              val newLeaf = new Leaf(key, v, r.nextLeafKey)
              r.nextLeafKey = key
              val newR = VerifierNode(LabelOnlyNode(r.label), LabelOnlyNode(newLeaf.label), 0: Byte)
              (newR, true, true, oldLabel)
            case _ =>
              (r, false, false, oldLabel)
          }
        case GoingLeft =>
          val rightLabel: Label = dequeueRightLabel(proof)
          val balance: Balance = dequeueBalance(proof)

          val (newLeftM, changeHappened, childHeightIncreased, oldLeftLabel) = verifyHelper()

          val r = VerifierNode(LabelOnlyNode(oldLeftLabel), LabelOnlyNode(rightLabel), balance)
          val oldLabel = r.label

          // balance = -1 if left higher, +1 if left lower
          if (changeHappened) {
            if (childHeightIncreased && r.balance < 0) {
              // need to rotate
              newLeftM match {
                // at this point we know newleftM must be an internal node an not a leaf -- b/c height increased;
                case newLeft: VerifierNode =>
                  if (newLeft.balance < 0) {
                    // single rotate
                    r.left = newLeft.right
                    r.balance = 0: Byte
                    newLeft.right = r
                    newLeft.balance = 0: Byte
                    (newLeft, true, false, oldLabel)
                  }

                  else {
                    // double rotate
                    val newRootM = newLeft.right
                    val newRoot = newRootM.asInstanceOf[VerifierNode]

                    r.left = newRoot.right
                    newRoot.right = r
                    newLeft.right = newRoot.left
                    newRoot.left = newLeft
                    newRoot.balance match {
                      case 0 =>
                        // newRoot is a newly created node
                        newLeft.balance = 0: Byte
                        r.balance = 0: Byte
                      case -1 =>
                        newLeft.balance = 0: Byte
                        r.balance = 1: Byte
                      case 1 =>
                        newLeft.balance = -1: Byte
                        r.balance = 0: Byte
                    }
                    newRoot.balance = 0: Byte
                    (newRoot, true, false, oldLabel)
                  }

                case newLeft =>
                  throw new Error("Got a leaf, internal node expected")
              }

            } else {
              // no need to rotate
              r.left = newLeftM
              val myHeightIncreased: Boolean = childHeightIncreased && (r.balance == (0: Byte))
              if (childHeightIncreased) r.balance = (r.balance - 1).toByte
              (r, true, myHeightIncreased, oldLabel)
            }

          } else {
            // no change happened
            (r, false, false, oldLabel)
          }

        case GoingRight =>
          val leftLabel: Label = dequeueLeftLabel(proof)
          val balance: Balance = dequeueBalance(proof)


          val (newRightM, changeHappened, childHeightIncreased, oldRightLabel) = verifyHelper()

          val r = VerifierNode(LabelOnlyNode(leftLabel), LabelOnlyNode(oldRightLabel), balance)
          val oldLabel = r.label

          if (changeHappened) {
            if (childHeightIncreased && r.balance > 0) {
              // need to rotate
              newRightM match {
                // at this point we know newRightM must be an internal node an not a leaf -- b/c height increased
                case newRight: VerifierNode =>
                  if (newRight.balance > 0) {
                    // single rotate
                    r.right = newRight.left
                    r.balance = 0: Byte
                    newRight.left = r
                    newRight.balance = 0: Byte
                    (newRight, true, false, oldLabel)
                  }

                  else {
                    // double rotate
                    val newRootM = newRight.left
                    val newRoot = newRootM.asInstanceOf[VerifierNode]

                    r.right = newRoot.left
                    newRoot.left = r
                    newRight.left = newRoot.right
                    newRoot.right = newRight

                    newRoot.balance match {
                      case 0 =>
                        // newRoot is a newly created node
                        newRight.balance = 0: Byte
                        r.balance = 0: Byte
                      case -1 =>
                        newRight.balance = 1: Byte
                        r.balance = 0: Byte
                      case 1 =>
                        newRight.balance = 0: Byte
                        r.balance = -1: Byte
                    }
                    newRoot.balance = 0: Byte

                    (newRoot, true, false, oldLabel)
                  }

                case newRight =>
                  throw new Error("Got a leaf, internal node expected")
              }
            } else {
              // no need to rotate
              r.right = newRightM
              val myHeightIncreased: Boolean = childHeightIncreased && r.balance == (0: Byte)
              if (childHeightIncreased) r.balance = (r.balance + 1).toByte
              (r, true, myHeightIncreased, oldLabel)
            }
          } else {
            // no change happened
            (r, false, false, oldLabel)
          }
      }
    }

    val (newTopNode, changeHappened, heighIncreased, oldLabel) = verifyHelper()
    if (oldLabel sameElements digest) {
      Some(newTopNode.label)
    } else {
      None
    }
  }.getOrElse(None)

}

object AVLModifyProof {

  def parseBytes(bytes: Array[Byte])(implicit keyLength: Int = 32, digestSize: Int = 32,
                                     hf: ThreadUnsafeHash = new Blake2b256Unsafe): Try[AVLModifyProof] = Try {
    val pathLength: Int = bytes.head
    require(pathLength % 3 == 0)

    val key = bytes.slice(1, 1 + keyLength)
    val pathProofs: Seq[AVLProofElement] = (0 until pathLength / 3) flatMap { i: Int =>
      val start = 1 + keyLength + i * (1 + 32)
      val (direction, balance) = parseDirectionBalance(bytes.slice(start, start + 1).head)
      val labelBytes = bytes.slice(start + 1, start + 1 + digestSize)
      val label = direction.direction match {
        case GoingLeft => ProofRightLabel(labelBytes)
        case GoingRight => ProofLeftLabel(labelBytes)
        case _ => throw new Error("Incorrect direction in internal node")
      }

      Seq(direction, label, balance)
    }
    val point = 1 + keyLength + pathLength * (32 + 1) / 3
    val (found, lastDirectionB) = splitBytes(bytes(point))

    val lastDirection = parseDirection(lastDirectionB)
    require(lastDirection.isLeaf, "Incorrect direction in leaf")
    val nextLeafKey: ProofNextLeafKey = ProofNextLeafKey(bytes.slice(point + 1, point + 1 + keyLength))
    val l = if (found == (1: Byte)) {
      val value: ProofValue = ProofValue(bytes.slice(point + 1 + keyLength, bytes.length))
      Seq(nextLeafKey, value)
    } else {
      val proofKey: ProofKey = ProofKey(bytes.slice(point + 1 + keyLength, point + 1 + 2 * keyLength))
      val value: ProofValue = ProofValue(bytes.slice(point + 1 + 2 * keyLength, bytes.length))
      Seq(proofKey, nextLeafKey, value)
    }
    AVLModifyProof(key, pathProofs ++ (lastDirection +: l))
  }

  private def parseDirection(byte: Byte): ProofDirection = ProofDirection(byte match {
    case 1 => LeafFound
    case 2 => LeafNotFound
    case 3 => GoingLeft
    case 4 => GoingRight
  })

  def combineBytes(b1: Byte, b2: Byte): Byte = ((b1 << 4) | (b2 + 1)).toByte

  def splitBytes(b: Byte): (Byte, Byte) = ((b >>> 4).toByte, ((b & 15) - 1).toByte)

  def directionBalanceByte(dir: ProofDirection, balance: ProofBalance): Byte =
    combineBytes(dir.bytes.head, balance.bytes.head)

  def parseDirectionBalance(b: Byte): (ProofDirection, ProofBalance) = {
    val (b1, b2) = splitBytes(b)
    (parseDirection(b1), ProofBalance(b2))
  }


}