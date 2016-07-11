package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import play.api.libs.json._
import scorex.crypto.authds.AuthData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.annotation.tailrec
import scala.util.Try

sealed trait SLProof extends AuthData[SLPath] {
  type Digest = CryptographicHash#Digest

  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean

  def bytes: Array[Byte]

  /**
   * Returns false if the element is in skiplist, true otherwise.
   */
  def isEmpty: Boolean

  /**
   * Returns true if the element is in skiplist, false otherwise.
   */
  def isDefined: Boolean = !isEmpty


}

/**
 * SLProof that is enough to recalculate root hash without whole skiplist
 * @param e - element to proof
 * @param l - proof of the element left to e 
 * @param r - proof of the element e if it's in skiplist, or proof right to it if it is not
 */
case class ExtendedSLProof(e: SLElement, l: SLExistenceProof, r: Option[SLExistenceProof]) extends SLProof {

  override def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    r.map(r => l.leftNeighborTo(r) && r.check(rootHash) && e <= r.e).getOrElse(true) && l.check(rootHash) && e > l.e
  }

  override def bytes: Array[Byte] = ???

  override def isEmpty: Boolean = !r.exists(r => r.e == e)
}

object ExtendedSLProof {
  type Digest = CryptographicHash#Digest

  def recalculate[HF <: CommutativeHash[_]](proofs: Seq[ProofToRecalculate], height: Int)
                                           (implicit hf: HF): Digest = {
    recalculateProofs(proofs, height).head.proof.l.rootHash()
  }

  //update proofs from tight to left
  def recalculateProofs[HF <: CommutativeHash[_]](proofs: Seq[ProofToRecalculate], height: Int)
                                                 (implicit hf: HF): Seq[ProofToRecalculate] = {

    //TODO fix
    require(proofs.length < 2 || proofs.forall(_.proof.isDefined), "Insert is not available for more then 1 element")

    @tailrec
    def loop(proofsRest: Seq[ProofToRecalculate], lev: Int, acc: Seq[ProofToRecalculate]): Seq[ProofToRecalculate] = {

      //pairs of old and rew elements in self chain
      @tailrec
      def calcNewSelfElements(vOld: Digest, vNew: Digest, restProofs: Seq[LevHash],
                              acc: Seq[(LevHash, LevHash)],
                              toInsert: Seq[(LevHash, LevHash)] = Seq()): Seq[(LevHash, LevHash)] = {
        if (restProofs.nonEmpty) {
          val current = acc.find(p => p._1.h sameElements restProofs.head.h).map(_._2).getOrElse(restProofs.head)
          val oldSelf = hf(vOld, restProofs.head.h)
          val oldLH = LevHash(oldSelf, current.l, current.d)
          val pair = toInsert.find(t => (t._1.h sameElements current.h) || (t._1.h sameElements oldSelf)) match {
            case Some(ti) =>
              if (ti._1.h sameElements current.h) {
                Seq((oldLH, LevHash(hf(hf(vNew, ti._2.h), current.h), ti._2.l, ti._2.d)))
              } else {
                val newLevHash: LevHash = LevHash(hf(vNew, current.h), current.l, current.d)
                Seq((oldLH, newLevHash))
                Seq((oldLH, LevHash(hf(ti._2.h, hf(vNew, current.h)), ti._2.l, ti._2.d)))
              }
            case None =>
              val newLevHash: LevHash = LevHash(hf(vNew, current.h), current.l, current.d)
              Seq((oldLH, newLevHash))
          }
          calcNewSelfElements(oldSelf, pair.last._2.h, restProofs.tail, pair ++ acc, toInsert)
        } else {
          acc
        }
      }
      def recalcOne(p: SLExistenceProof, toReplace: Seq[(LevHash, LevHash)], toRemove: Seq[LevHash] = Seq(),
                    toInsert: Seq[(LevHash, LevHash)] = Seq()): SLExistenceProof = {
        val filtered = toReplace.filter(tr => !(tr._1.h sameElements tr._2.h))
        val (inserted, _) = p.proof.levHashes.foldLeft((Seq[LevHash](), hf(p.e.bytes))) { (pair, y) =>
          val hash = hf(pair._2, y.h)
          toInsert.find(ti => (ti._1.h sameElements hash) || (ti._1.h sameElements y.h)) match {
            case None => (y +: pair._1, hash)
            case Some(h) =>
              if (h._1.h sameElements hash) {
                (h._2 +: (y +: pair._1), hash)
              } else {
                val nh: LevHash = LevHash(hf(h._2.h, y.h), h._2.l, h._2.d)
                (nh +: pair._1, hash)
              }

          }
        }

        val newHashes: Seq[LevHash] = inserted.reverse.flatMap { lh =>
          def r(h: Digest, l: Int, d: Direction): Seq[LevHash] = {
            filtered.find(tr => h sameElements tr._1.h).map(_._2) match {
              case Some(repl) => r(repl.h, l, d)
              case None => Seq(LevHash(h, l, d))
            }
          }
          r(lh.h, lh.l, lh.d).filter(e => !toRemove.contains(e))
        }

        val newPath = SLPath(newHashes)
        p.copy(proof = newPath)
      }

      val rightProof = proofsRest.head
      val leftProofs = proofsRest.tail

      val (toReplace, newRightProof, toInsert, toRemove) = rightProof.proof.r match {
        case Some(r) if rightProof.proof.isDefined =>
          // update

          val elHashesR = (LevHash(hf(rightProof.proof.e.bytes), 0, Down), LevHash(hf(rightProof.newEl.bytes), 0, Down))
          val toReplaceR = calcNewSelfElements(elHashesR._1.h, elHashesR._2.h, r.proof.levHashes, Seq(elHashesR))

          val headReplace = if (rightProof.proof.l.proof.hashes.head sameElements hf(rightProof.proof.e.bytes)) {
            hf(rightProof.newEl.bytes)
          } else {
            hf(hf(rightProof.newEl.bytes), r.proof.hashes.head)
          }

          val newLRproof = recalcOne(rightProof.proof.l, toReplaceR)
          val elHashesL = (LevHash(newLRproof.proof.hashes.head, 0, Right), LevHash(headReplace, 0, Right))
          val oldLeftHash = hf(hf(rightProof.proof.l.e.bytes), rightProof.proof.l.proof.hashes.head)
          val newLeftHash = hf(hf(rightProof.proof.l.e.bytes), headReplace)

          val toReplaceL = (LevHash(oldLeftHash, 0, Right), LevHash(newLeftHash, 0, Right)) +:
            calcNewSelfElements(oldLeftHash, newLeftHash, newLRproof.proof.levHashes.tail, Seq(elHashesL))

          val newRRproof = rightProof.proof.r.map(_.copy(e = rightProof.newEl)).map(recalcOne(_, toReplaceL))
          val newRightProof = rightProof.copy(proof = ExtendedSLProof(rightProof.newEl, newLRproof, newRRproof))
          val toReplace = toReplaceL ++ toReplaceR
          (toReplace, newRightProof, Seq(), Seq())
        case _ =>
          //insert

          val insertLevel = SkipList.selectLevel(rightProof.newEl, lev)
          val hashesFromRight: Seq[LevHash] = rightProof.proof.l.proof.levHashes.filter(_.d == Right)
          // all this hashes are taken by newEl with increasing level
          val takenByNewElement: Seq[LevHash] = hashesFromRight.filter(_.l <= insertLevel)
          val topTaken = takenByNewElement.last
          val toRemove = if (topTaken.l == insertLevel && insertLevel > 0) takenByNewElement.filter(_.l < insertLevel)
          else takenByNewElement

          //first level hash of new elements
          val rightSelfHash = hf(hf(rightProof.newEl.bytes), rightProof.proof.l.proof.hashes.head)
          //top level ()in a tower hash of new element
          val newElHash: LevHash = LevHash(hashesFromRight.foldLeft(hf(rightProof.newEl.bytes)) { (x, y) =>
            if (y.l > insertLevel) x
            else hf(x, y.h)
          }, insertLevel, Right)

          val toInsert: Seq[(LevHash, LevHash)] = if (insertLevel > 0 && topTaken.l != insertLevel) {
            Seq({
              val toCalc = rightProof.proof.l.proof.levHashes.filter(_.l < insertLevel)
              val hash = toCalc.foldLeft(hf(rightProof.proof.l.e.bytes))((x, y) => hf(x, y.h))
              (LevHash(hash, toCalc.last.l, toCalc.last.d), newElHash)
            })
          } else Seq()

          val headReplace = if (insertLevel == 0) {
            rightSelfHash
          } else {
            hf(rightProof.newEl.bytes)
          }

          val leftHead = rightProof.proof.l.proof.levHashes.head
          val sameLevel = if (topTaken.l == insertLevel && insertLevel > 0) Seq((topTaken, newElHash)) else Seq()
          val toReplaceR = sameLevel ++ Seq((leftHead, LevHash(headReplace, 0, Right)))

          val newLRproof = recalcOne(rightProof.proof.l, toReplaceR, toRemove.tail, toInsert)

          val elHashesL = (leftHead, LevHash(rightSelfHash, leftHead.l, leftHead.d))
          val oldLeftHash = hf(hf(rightProof.proof.l.e.bytes), leftHead.h)
          val newLeftHash = hf(hf(rightProof.proof.l.e.bytes), headReplace)
          val toReplaceL = (LevHash(oldLeftHash, 0, leftHead.d), LevHash(newLeftHash, 0, leftHead.d)) +:
            calcNewSelfElements(oldLeftHash, newLeftHash, rightProof.proof.l.proof.levHashes.tail, elHashesL +: toReplaceR, toInsert = toInsert).reverse

          val newRRproof = rightProof.proof.r.map(_.copy(e = rightProof.newEl)).map(recalcOne(_, toReplaceL))
          val newRightProof = rightProof.copy(proof = ExtendedSLProof(rightProof.newEl, newLRproof, newRRproof))
          val toReplace = toReplaceL ++ toReplaceR
          val toInsertForAll = toInsert.filter(ti => !toReplaceL.map(_._1).exists(_.h sameElements ti._1.h))
          (toReplace, newRightProof, toInsertForAll, toRemove)
      }

      val recalculated: Seq[ProofToRecalculate] = leftProofs map { p =>
        if (p.proof.isEmpty && p.proof.l.e == newRightProof.proof.l.e) {
          //insert element to the same position
          val newExtended = p.proof.copy(l = newRightProof.proof.l, r = newRightProof.proof.r)
          p.copy(proof = newExtended)
        } else {
          val newRight = p.proof.r.map(recalcOne(_, toReplace, toRemove, toInsert))
          val newLeft = recalcOne(p.proof.l, toReplace, toRemove, toInsert)
          val newExtended = p.proof.copy(l = newLeft, r = newRight)
          p.copy(proof = newExtended)
        }
      }
      if (proofsRest.tail.nonEmpty) {
        loop(recalculated, Math.max(lev + 1, height), newRightProof +: acc)
      } else newRightProof +: acc
    }

    loop(proofs.sortBy(_.newEl).reverse, height, Seq())
  }
}

/**
 *
 * @param newEl - element to put to that position
 * @param proof - proof of newEl and element left to it
 */
case class ProofToRecalculate(newEl: SLElement, proof: ExtendedSLProof)

/**
 *
 * @param e
 * @param l
 * @param r - None for MaxSlElement, Some for others
 */
case class SLNonExistenceProof(e: SLElement, l: SLExistenceProof, r: Option[SLExistenceProof]) extends SLProof {
  lazy val bytes: Array[Byte] = {
    val eSize = Ints.toByteArray(e.bytes.length)
    val leftSize = Ints.toByteArray(l.bytes.length)
    val rightSize = Ints.toByteArray(r.map(r => r.bytes.length).getOrElse(0))

    Array(0: Byte) ++ eSize ++ leftSize ++ rightSize ++ e.bytes ++ l.bytes ++ r.map(_.bytes).getOrElse(Array())
  }

  override def isEmpty: Boolean = true

  override def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hf: HF): Boolean = {
    val linked: Boolean = r match {
      case None => l.proof.hashes.head sameElements hf(MaxSLElement.bytes)
      case Some(rp) => l.leftNeighborTo(rp)
    }
    val rightCheck = r.map(rp => e < rp.e && rp.check(rootHash)).getOrElse(true)

    linked && e > l.e && l.check(rootHash)
  }
}

/**
 * @param e - element to proof
 * @param proof - skiplist path, complementary to data block
 */
case class SLExistenceProof(e: SLElement, proof: SLPath) extends SLProof {

  def leftNeighborTo[HF <: CommutativeHash[_]](that: SLExistenceProof)(implicit hf: HF): Boolean = {
    val tower = proof.hashes.head sameElements hf(that.e.bytes)
    val nonTower = proof.hashes.head sameElements hf(hf(that.e.bytes), that.proof.hashes.head)
    tower || nonTower
  }

  override def isEmpty: Boolean = false

  lazy val bytes: Array[Byte] = {
    require(proof.hashes.nonEmpty, "Merkle path cannot be empty")
    val dataSize = Ints.toByteArray(e.bytes.length)
    val proofLength = Ints.toByteArray(proof.hashes.length)
    val proofSize = Ints.toByteArray(proof.hashes.head.length)
    val proofBytes = proof.hashes.foldLeft(Array.empty: Array[Byte])((b, mp) => b ++ mp)
    Array(1: Byte) ++ dataSize ++ proofLength ++ proofSize ++ e.bytes ++ proofBytes
  }

  /**
   * Checks that this block is at position $index in tree with root hash = $rootHash
   */
  def check[HF <: CommutativeHash[_]](currentRootHash: Digest)(implicit hashFunction: HF): Boolean = {
    rootHash() sameElements currentRootHash
  }


  def rootHash[HF <: CommutativeHash[_]]()(implicit hashFunction: HF): Digest = {
    proof.hashes.foldLeft(hashFunction.hash(e.bytes)) { (x, y) =>
      hashFunction.hash(x, y)
    }
  }
}


object SLProof {
  def decode[HashFunction <: CryptographicHash](bytes: Array[Byte]): Try[SLProof] = Try {
    if (bytes.head == (1: Byte)) {
      decodeExistenceProof(bytes.tail)
    } else {
      decodeNonExistenceProof(bytes.tail)
    }
  }

  private def decodeNonExistenceProof[HashFunction <: CryptographicHash](bytes: Array[Byte]): SLNonExistenceProof = {
    val eSize = Ints.fromByteArray(bytes.slice(0, 4))
    val leftSize = Ints.fromByteArray(bytes.slice(4, 8))
    val rightSize = Ints.fromByteArray(bytes.slice(8, 12))
    val e = SLElement.parseBytes(bytes.slice(12, 12 + eSize)).get
    val left = decodeExistenceProof(bytes.slice(12 + eSize, 12 + eSize + leftSize).tail)
    val right = if (rightSize == 0) None
    else Some(decodeExistenceProof(bytes.slice(12 + eSize + leftSize, 12 + eSize + leftSize + rightSize).tail))
    SLNonExistenceProof(e, left, right)
  }

  private def decodeExistenceProof[HashFunction <: CryptographicHash](bytes: Array[Byte]): SLExistenceProof = {
    val dataSize = Ints.fromByteArray(bytes.slice(0, 4))
    val merklePathLength = Ints.fromByteArray(bytes.slice(4, 8))
    val merklePathSize = Ints.fromByteArray(bytes.slice(8, 12))
    val data = bytes.slice(12, 12 + dataSize)
    val e = SLElement.parseBytes(data).get
    val merklePathStart = 12 + dataSize
    val merklePath = (0 until merklePathLength).map { i =>
      bytes.slice(merklePathStart + i * merklePathSize, merklePathStart + (i + 1) * merklePathSize)
    }
    //TODO parse levels and directions
    SLExistenceProof(e, SLPath(merklePath.map(h => LevHash(h, -1, Down))))
  }
}

object SLExistenceProof {
  implicit def authDataBlockReads[T, HashFunction <: CryptographicHash]
  (implicit fmt: Reads[T]): Reads[SLExistenceProof] = new Reads[SLExistenceProof] {
    def reads(json: JsValue): JsResult[SLExistenceProof] = JsSuccess(SLExistenceProof(
      Base58.decode((json \ "data").as[String]).flatMap(SLElement.parseBytes).get,
      SLPath(
        (json \ "merklePath").get match {
          case JsArray(ts) => ts.map { t =>
            t match {
              case JsString(digest) =>
                Base58.decode(digest)
              case m =>
                throw new RuntimeException("MerklePath MUST be array of strings" + m + " given")
            }
          }.map(h => LevHash(h.get, -1, Down))
          //TODO parse levels
          case m =>
            throw new RuntimeException("MerklePath MUST be a list " + m + " given")
        })
    ))
  }

  implicit def authDataBlockWrites[T, HashFunction <: CryptographicHash](implicit fmt: Writes[T]): Writes[SLExistenceProof]
  = new Writes[SLExistenceProof] {
    def writes(ts: SLExistenceProof) = JsObject(Seq(
      "data" -> JsString(Base58.encode(ts.e.bytes)),
      "merklePath" -> JsArray(
        ts.proof.hashes.map(digest => JsString(Base58.encode(digest)))
      )
    ))
  }
}