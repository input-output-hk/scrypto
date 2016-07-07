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
 */
sealed trait ExtendedSLProof extends SLProof

case class ExtendedSLExistenceProof(l: SLExistenceProof, r: SLExistenceProof) extends ExtendedSLProof {
  override def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    l.leftNeighborTo(r) && l.check(rootHash) && r.check(rootHash)
  }

  override def bytes: Array[Byte] = ???

  override def isEmpty: Boolean = false
}

object ExtendedSLProof {
  type Digest = CryptographicHash#Digest

  def recalculate[HF <: CommutativeHash[_]](proofs: Seq[ProofToRecalculate])
                                           (implicit hf: HF): Digest = {
    recalculateProofs(proofs).head.eProof.l.rootHash()
  }

  //update proofs from tight to left
  def recalculateProofs[HF <: CommutativeHash[_]](proofs: Seq[ProofToRecalculate])
                                                 (implicit hf: HF): Seq[ProofToRecalculate] = {
    @tailrec
    def loop(proofsRest: Seq[ProofToRecalculate], acc: Seq[ProofToRecalculate] = Seq()): Seq[ProofToRecalculate] = {
      //pairs of old and rew elements in self chain
      @tailrec
      def calcNewSelfElements(vOld: Digest, vNew: Digest, restProofs: Seq[LevHash],
                              acc: Seq[(LevHash, LevHash)]): Seq[(LevHash, LevHash)] = {
        if (restProofs.nonEmpty) {
          val currentProof = restProofs.head
          val lev = currentProof.l
          val pair: (LevHash, LevHash) = (LevHash(hf(vOld, currentProof.h), lev), LevHash(hf(vNew, currentProof.h), lev))
          calcNewSelfElements(pair._1.h, pair._2.h, restProofs.tail, pair +: acc)
        } else {
          acc
        }
      }
      def recalcOne(p: SLExistenceProof, toReplace: Seq[(LevHash, LevHash)]): SLExistenceProof = {
        val filtered = toReplace.filter(tr => !(tr._1.h sameElements tr._2.h))
        val newHashes: Seq[LevHash] = p.proof.levHashes.map { lh =>
          def r(h: LevHash): LevHash = filtered.find(tr => h.h sameElements tr._1.h).map(_._2) match {
            case Some(repl) => r(repl)
            case None => h

          }
          r(lh)
        }
        val newPath = SLPath(newHashes)
        p.copy(proof = newPath)
      }

      val rightProof = proofsRest.head
      val leftProofs = proofsRest.tail

      val elHashesR = (LevHash(hf(rightProof.eProof.r.e.bytes), 0), LevHash(hf(rightProof.newEl.bytes), 0))
      val toReplaceR = calcNewSelfElements(elHashesR._1.h, elHashesR._2.h, rightProof.eProof.r.proof.levHashes, Seq(elHashesR))

      val headReplace = if (rightProof.eProof.l.proof.hashes.head sameElements hf(rightProof.eProof.r.e.bytes)) {
        hf(rightProof.newEl.bytes)
      } else {
        hf(hf(rightProof.newEl.bytes), rightProof.eProof.r.proof.hashes.head)
      }

      val newLRproof = recalcOne(rightProof.eProof.l, toReplaceR)
      val elHashesL = (LevHash(newLRproof.proof.hashes.head, 0), LevHash(headReplace, 0))
      val oldLeftHash = hf(hf(rightProof.eProof.l.e.bytes), rightProof.eProof.l.proof.hashes.head)
      val newLeftHash = hf(hf(rightProof.eProof.l.e.bytes), headReplace)

      val toReplaceL = (LevHash(oldLeftHash, -1), LevHash(newLeftHash, -1)) +: calcNewSelfElements(oldLeftHash,
        newLeftHash, newLRproof.proof.levHashes.tail, Seq(elHashesL)).filter(tr => !(tr._1.h sameElements tr._2.h))

      val newRRproof = recalcOne(rightProof.eProof.r.copy(e = rightProof.newEl), toReplaceL)
      val newRightProof = rightProof.copy(eProof = ExtendedSLExistenceProof(newLRproof, newRRproof))
      val toReplace = toReplaceL ++ toReplaceR

      val recalculated: Seq[ProofToRecalculate] = leftProofs map { p =>
        val newRight = recalcOne(p.eProof.r, toReplace)
        val newLeft = recalcOne(p.eProof.l, toReplace)
        val newExtended = p.eProof.copy(l = newLeft, r = newRight)
        p.copy(eProof = newExtended)
      }
      if (proofsRest.tail.nonEmpty) {
        loop(recalculated, newRightProof +: acc)
      } else newRightProof +: acc
    }

    //right element proof will change cause it'll change left proof !!
    loop(proofs.sortBy(_.newEl).reverse, Seq())
  }

}

/**
 *
 * @param newEl - element to put to that position
 * @param eProof - proof of newEl and element left to it
 */
case class ProofToRecalculate(newEl: SLElement, eProof: ExtendedSLExistenceProof)

/**
 *
 * @param e
 * @param left
 * @param right - None for MaxSlElement, Some for others
 */
case class SLNonExistenceProof(e: SLElement, left: SLExistenceProof, right: Option[SLExistenceProof]) extends SLProof
with ExtendedSLProof {
  lazy val bytes: Array[Byte] = {
    val eSize = Ints.toByteArray(e.bytes.length)
    val leftSize = Ints.toByteArray(left.bytes.length)
    val rightSize = Ints.toByteArray(right.map(r => r.bytes.length).getOrElse(0))

    Array(0: Byte) ++ eSize ++ leftSize ++ rightSize ++ e.bytes ++ left.bytes ++ right.map(_.bytes).getOrElse(Array())
  }

  override def isEmpty: Boolean = true

  override def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hf: HF): Boolean = {
    val linked: Boolean = right match {
      case None => left.proof.hashes.head sameElements hf(MaxSLElement.bytes)
      case Some(rp) => left.leftNeighborTo(rp)
    }
    val rightCheck = right.map(rp => e < rp.e && rp.check(rootHash)).getOrElse(true)

    linked && e > left.e && left.check(rootHash)
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
    //TODO parse levels
    SLExistenceProof(e, SLPath(merklePath.map(h => LevHash(h, -1))))
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
          }.map(h => LevHash(h.get, -1))
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