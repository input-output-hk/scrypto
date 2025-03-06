package scorex.crypto.authds.legacy.avltree

import scorex.crypto.authds._
import scorex.crypto.authds.avltree.batch.Modification
import scorex.crypto.hash.{CryptographicHash, _}
import scorex.utils.{ByteArray, Bytes}

import scala.util.{Try, Success, Failure}

case class AVLModifyProof(key: ADKey, proofSeq: Seq[AVLProofElement])
                         (implicit hf: CryptographicHash[_ <: Digest]) extends TwoPartyProof {
  type ChangeHappened = Boolean
  type HeightIncreased = Boolean


  def verifyLookup(digest: ADDigest, existence: Boolean): Option[ADDigest] = {
    def existenceLookupFunction: Option[ADValue] => Try[Option[ADValue]] = {
      case Some(v) => Success(Some(v))
      case None => Failure(new Error("Key not found"))
    }

    def nonExistenceLookupFunction: Option[ADValue] => Try[Option[ADValue]] = {
      case Some(v) => Failure(new Error("Key found"))
      case None => Success(None)
    }

    if (existence) {
      verify(digest, existenceLookupFunction)
    } else {
      verify(digest, nonExistenceLookupFunction)
    }
  }

  /**
    * Returns the new root and indicators whether tree has been modified at r or below
    * and whether the height has increased
    * Also returns the label of the old root
    */
  private def verifyHelper(updateFn: Modification#UpdateFunction): (VerifierNodes, ChangeHappened, HeightIncreased, Digest) = {
    dequeueDirection() match {
      case LeafFound =>
        val nextLeafKey: ADKey = dequeueNextLeafKey()
        val value: ADValue = dequeueValue()

        updateFn(Some(value)) match {
          case Success(None) => //delete value
            ???
          case Success(Some(v)) => //update value
            val oldLeaf = Leaf(key, value, nextLeafKey)
            val newLeaf = Leaf(key, v, nextLeafKey)
            (newLeaf, true, false, oldLeaf.label)
          case Failure(e) => // found incorrect value
            throw e
        }


      case LeafNotFound =>
        val neighbourLeafKey = dequeueKey()
        val nextLeafKey: ADKey = dequeueNextLeafKey()
        val value: ADValue = dequeueValue()
        require(ByteArray.compare(neighbourLeafKey, key) < 0)
        require(ByteArray.compare(key, nextLeafKey) < 0)

        val r = Leaf(neighbourLeafKey, value, nextLeafKey)
        val oldLabel = r.label
        updateFn(None) match {
          case Success(None) => //don't change anything, just lookup
            (r, false, false, oldLabel)
          case Success(Some(v)) => //insert new value
            val newLeaf = Leaf(key, v, r.nextLeafKey)
            r.nextLeafKey = key
            val newR = VerifierNode(LabelOnlyNode(r.label), LabelOnlyNode(newLeaf.label), Balance @@ 0.toByte)
            (newR, true, true, oldLabel)
          case Failure(e) => // found incorrect value
            // (r, false, false, oldLabel)
            throw e
        }
      case GoingLeft =>
        val rightLabel: Digest = dequeueRightLabel()
        val balance: Balance = dequeueBalance()

        val (newLeftM, changeHappened, childHeightIncreased, oldLeftLabel) = verifyHelper(updateFn)

        val r = VerifierNode(LabelOnlyNode(oldLeftLabel), LabelOnlyNode(rightLabel), balance)
        val oldLabel = r.label

        // balance = -1 if left higher, +1 if left lower
        if (changeHappened) {
          if (childHeightIncreased && r.balance < 0) {
            // need to rotate
            newLeftM match {
              // at this point we know newLeftM must be an internal node an not a leaf -- b/c height increased;
              case newLeft: VerifierNode =>
                if (newLeft.balance < 0) {
                  // single rotate
                  r.left = newLeft.right
                  r.balance = Balance @@ 0.toByte
                  newLeft.right = r
                  newLeft.balance = Balance @@ 0.toByte
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
                    case a if a == 0 =>
                      // newRoot is a newly created node
                      newLeft.balance = Balance @@ 0.toByte
                      r.balance = Balance @@ 0.toByte
                    case a if a == -1 =>
                      newLeft.balance = Balance @@ 0.toByte
                      r.balance = Balance @@ 1.toByte
                    case a if a == 1 =>
                      newLeft.balance = Balance @@ (-1.toByte)
                      r.balance = Balance @@ 0.toByte
                  }
                  newRoot.balance = Balance @@ 0.toByte
                  (newRoot, true, false, oldLabel)
                }

              case newLeft =>
                throw new Error("Got a leaf, internal node expected")
            }

          } else {
            // no need to rotate
            r.left = newLeftM
            val myHeightIncreased: Boolean = childHeightIncreased && (r.balance == (0: Byte))
            if (childHeightIncreased) r.balance = Balance @@ (r.balance - 1).toByte
            (r, true, myHeightIncreased, oldLabel)
          }

        } else {
          // no change happened
          (r, false, false, oldLabel)
        }

      case GoingRight =>
        val leftLabel: Digest = dequeueLeftLabel()
        val balance: Balance = dequeueBalance()

        val (newRightM, changeHappened, childHeightIncreased, oldRightLabel) = verifyHelper(updateFn)

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
                  r.balance = Balance @@ 0.toByte
                  newRight.left = r
                  newRight.balance = Balance @@ 0.toByte
                  (newRight, true, false, oldLabel)
                } else {
                  // double rotate
                  val newRootM = newRight.left
                  val newRoot = newRootM.asInstanceOf[VerifierNode]

                  r.right = newRoot.left
                  newRoot.left = r
                  newRight.left = newRoot.right
                  newRoot.right = newRight

                  newRoot.balance match {
                    case a if a == 0 =>
                      // newRoot is a newly created node
                      newRight.balance = Balance @@ 0.toByte
                      r.balance = Balance @@ 0.toByte
                    case a if a == -1 =>
                      newRight.balance = Balance @@ 1.toByte
                      r.balance = Balance @@ 0.toByte
                    case a if a == 1 =>
                      newRight.balance = Balance @@ 0.toByte
                      r.balance = Balance @@ -1.toByte
                  }
                  newRoot.balance = Balance @@ 0.toByte

                  (newRoot, true, false, oldLabel)
                }

              case newRight =>
                throw new Error("Got a leaf, internal node expected")
            }
          } else {
            // no need to rotate
            r.right = newRightM
            val myHeightIncreased: Boolean = childHeightIncreased && r.balance == (0: Byte)
            if (childHeightIncreased) r.balance = Balance @@ (r.balance + 1).toByte
            (r, true, myHeightIncreased, oldLabel)
          }
        } else {
          // no change happened
          (r, false, false, oldLabel)
        }
    }
  }

  def verify(digest: ADDigest, updateFn: Modification#UpdateFunction): Option[ADDigest] = Try {
    initializeIterator()

    val (newTopNode, _, _, oldLabel) = verifyHelper(updateFn)
    if (oldLabel sameElements digest) Some(ADDigest @@@ newTopNode.label) else None
  }.getOrElse(None)

  /**
    * seqLength, key, ++
    * notFound: Seq(ProofDirection, ProofLabel, ProofBalance), ProofDirection, ProofKey, ProofNextLeafKey, ProofValue
    * found: Seq(ProofDirection, ProofLabel, ProofBalance), ProofDirection, ProofNextLeafKey, ProofValue
    */
  lazy val bytes: Array[Byte] = {
    val keyFound = proofSeq.length % 3 == 0

    val pathLength = if (keyFound) proofSeq.length - 3 else proofSeq.length - 4
    val inBytes = pathLength.toByte +: key
    val pathProofsBytes: Array[Byte] = (0 until pathLength / 3).toArray.flatMap { (i: Int) =>
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
}

object AVLModifyProof {

  def parseBytes(bytes: Array[Byte])(implicit keyLength: Int = 32, digestSize: Int = 32,
                                     hf: CryptographicHash[_ <: Digest] = Blake2b256): Try[AVLModifyProof] = Try {
    val pathLength: Int = bytes.head.ensuring(_ % 3 == 0)

    val key = ADKey @@ bytes.slice(1, 1 + keyLength)
    val pathProofs: Seq[AVLProofElement] = (0 until pathLength / 3) flatMap { (i: Int) =>
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

  def splitBytes(b: Byte): (Byte, Balance) = ((b >>> 4).toByte, Balance @@ ((b & 15) - 1).toByte)

  def directionBalanceByte(dir: ProofDirection, balance: ProofBalance): Byte =
    combineBytes(dir.bytes.head, balance.bytes.head)

  def parseDirectionBalance(b: Byte): (ProofDirection, ProofBalance) = {
    val (b1, b2) = splitBytes(b)
    (parseDirection(b1), ProofBalance(b2))
  }
}