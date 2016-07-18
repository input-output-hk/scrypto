package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.annotation.tailrec
import scala.util.Try

/**
 * SLProof that is enough to recalculate root hash without whole skiplist
 * @param e - element to proof
 * @param l - proof of the element left to e
 * @param r - proof of the element e if it's in skiplist, or proof right to it if it is not
 */
case class ExtendedSLProof(e: SLElement, l: SLExistenceProof, r: Option[SLExistenceProof]) extends SLProofI {

  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    r.map(r => l.leftNeighborTo(r) && r.check(rootHash) && e <= r.e).getOrElse(true) && l.check(rootHash) && e > l.e
  }

  lazy val bytes: Array[Byte] = {
    val eSize = Ints.toByteArray(e.bytes.length)
    val leftSize = Ints.toByteArray(l.bytes.length)
    val rightSize = Ints.toByteArray(r.map(r => r.bytes.length).getOrElse(0))

    eSize ++ leftSize ++ rightSize ++ e.bytes ++ l.bytes ++ r.map(_.bytes).getOrElse(Array())
  }

  def isEmpty: Boolean = !r.exists(r => r.e == e)
}

object ExtendedSLProof {
  type Digest = CryptographicHash#Digest

  def recalculate[HF <: CommutativeHash[_]](proofs: Seq[ProofToRecalculate], height: Int)
                                           (implicit hf: HF): Digest = {
    recalculateProofs(proofs, height).head.proof.l.rootHash()
  }

  def recalculateProof[HF <: CommutativeHash[_]](p: ProofToRecalculate, lev: Int)(implicit hf: HF): (Digest, Int) = {
    val r = recalculateOneProof(p, lev)
    (r._3.proof.l.rootHash(), r._1)
  }

  //update proofs from tight to left
  def recalculateProofs[HF <: CommutativeHash[_]](proofs: Seq[ProofToRecalculate], height: Int)
                                                 (implicit hf: HF): Seq[ProofToRecalculate] = {

    //TODO fix
    require(proofs.length < 2 || proofs.forall(_.proof.isDefined), "Insert is not available for more then 1 element")

    @tailrec
    def loop(proofsRest: Seq[ProofToRecalculate], lev: Int, acc: Seq[ProofToRecalculate]): Seq[ProofToRecalculate] = {

      val rightProof = proofsRest.head
      val leftProofs = proofsRest.tail

      val (insertLevel, toReplace, newRightProof, toInsert, toRemove) = recalculateOneProof(rightProof, lev)

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
        loop(recalculated, Math.max(insertLevel + 1, height), newRightProof +: acc)
      } else newRightProof +: acc
    }

    loop(proofs.sortBy(_.newEl).reverse, height, Seq())
  }

  private def recalculateOneProof[HF <: CommutativeHash[_]](rightProof: ProofToRecalculate, lev: Int)
                                                           (implicit hf: HF):
  (Int, Seq[(LevHash, LevHash)], ProofToRecalculate, Seq[(LevHash, LevHash)], Seq[LevHash]) = {

    rightProof.proof.r match {
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
        (lev, toReplace, newRightProof, Seq(), Seq())
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
        (insertLevel, toReplace, newRightProof, toInsertForAll, toRemove)
    }
  }

  //pairs of old and rew elements in self chain
  @tailrec
  def calcNewSelfElements[HF <: CommutativeHash[_]](vOld: Digest, vNew: Digest, restProofs: Seq[LevHash],
                                                    acc: Seq[(LevHash, LevHash)],
                                                    toInsert: Seq[(LevHash, LevHash)] = Seq())
                                                   (implicit hf: HF): Seq[(LevHash, LevHash)] = {
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
      calcNewSelfElements[HF](oldSelf, pair.last._2.h, restProofs.tail, pair ++ acc, toInsert)
    } else {
      acc
    }
  }

  def recalcOne[HF <: CommutativeHash[_]](p: SLExistenceProof, toReplace: Seq[(LevHash, LevHash)],
                                          toRemove: Seq[LevHash] = Seq(),
                                          toInsert: Seq[(LevHash, LevHash)] = Seq())
                                         (implicit hf: HF): SLExistenceProof = {
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

  def decode[HashFunction <: CryptographicHash](bytes: Array[Byte]): Try[ExtendedSLProof] = Try {
    val eSize = Ints.fromByteArray(bytes.slice(0, 4))
    val leftSize = Ints.fromByteArray(bytes.slice(4, 8))
    val rightSize = Ints.fromByteArray(bytes.slice(8, 12))
    val e = SLElement.parseBytes(bytes.slice(12, 12 + eSize)).get
    val left = SLProof.decodeExistenceProof(bytes.slice(12 + eSize, 12 + eSize + leftSize).tail)
    val right = if (rightSize == 0) None
    else Some(SLProof.decodeExistenceProof(bytes.slice(12 + eSize + leftSize, 12 + eSize + leftSize + rightSize).tail))
    ExtendedSLProof(e, left, right)
  }
}

