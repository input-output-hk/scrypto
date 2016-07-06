package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import play.api.libs.json._
import scorex.crypto.authds.AuthData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

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
 *
 * @param e
 * @param left
 * @param right - None for MaxSlElement, Some for others
 */
case class SLNonExistenceProof(e: SLElement, left: SLExistenceProof, right: Option[SLExistenceProof]) extends SLProof {
  lazy val bytes: Array[Byte] = {
    val eSize = Ints.toByteArray(e.bytes.length)
    val leftSize = Ints.toByteArray(left.bytes.length)
    val rightSize = Ints.toByteArray(right.map(r => r.bytes.length).getOrElse(0))

    Array(0: Byte) ++ eSize ++ leftSize ++ rightSize ++ e.bytes ++ left.bytes ++ right.map(_.bytes).getOrElse(Array())
  }

  override def isEmpty: Boolean = true

  override def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hf: HF): Boolean = {
    val linked: Boolean = right match {
      case None => left.proof.hashes.last sameElements hf(MaxSLElement.bytes)
      case Some(rp) =>
        val tower = left.proof.hashes.last sameElements hf(rp.e.bytes)
        val nonTower = left.proof.hashes.last sameElements hf.hash(hf(rp.e.bytes), rp.proof.hashes.last)
        tower || nonTower
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
  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    proof.hashes.reverse.foldLeft(hashFunction.hash(e.bytes)) { (x, y) =>
      hashFunction.hash(x, y)
    }.sameElements(rootHash)
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
    SLExistenceProof(e, SLPath(merklePath))
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
          }.map(_.get)
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