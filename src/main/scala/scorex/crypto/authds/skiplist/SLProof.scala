package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import play.api.libs.json._
import scorex.crypto.authds.AuthData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.annotation.tailrec
import scala.util.Try

sealed trait SLProof extends SLProofI

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
    val proofLength = Ints.toByteArray(proof.levHashes.length)
    val proofSize = Ints.toByteArray(proof.levHashes.head.bytes.length)
    val proofBytes = proof.levHashes.foldLeft(Array.empty: Array[Byte])((b, mp) => b ++ mp.bytes)
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
  def parseBytes(bytes: Array[Byte]): Try[SLProof] = Try {
    if (bytes.head == (1: Byte)) {
      decodeExistenceProof(bytes.tail)
    } else {
      decodeNonExistenceProof(bytes.tail)
    }
  }

  def decodeNonExistenceProof[HashFunction <: CryptographicHash](bytes: Array[Byte]): SLNonExistenceProof = {
    val eSize = Ints.fromByteArray(bytes.slice(0, 4))
    val leftSize = Ints.fromByteArray(bytes.slice(4, 8))
    val rightSize = Ints.fromByteArray(bytes.slice(8, 12))
    val e = SLElement.parseBytes(bytes.slice(12, 12 + eSize)).get
    val left = decodeExistenceProof(bytes.slice(12 + eSize, 12 + eSize + leftSize).tail)
    val right = if (rightSize == 0) None
    else Some(decodeExistenceProof(bytes.slice(12 + eSize + leftSize, 12 + eSize + leftSize + rightSize).tail))
    SLNonExistenceProof(e, left, right)
  }

  def decodeExistenceProof[HashFunction <: CryptographicHash](bytes: Array[Byte]): SLExistenceProof = {
    val dataSize = Ints.fromByteArray(bytes.slice(0, 4))
    val merklePathLength = Ints.fromByteArray(bytes.slice(4, 8))
    val merklePathSize = Ints.fromByteArray(bytes.slice(8, 12))
    val data = bytes.slice(12, 12 + dataSize)
    val e = SLElement.parseBytes(data).get
    val merklePathStart = 12 + dataSize
    val levHashes: Seq[LevHash] = (0 until merklePathLength).map { i =>
      LevHash.parseBytes(bytes.slice(merklePathStart + i * merklePathSize, merklePathStart + (i + 1) * merklePathSize)).get
    }
    SLExistenceProof(e, SLPath(levHashes))
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