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
  lazy val data = e.bytes
  lazy val bytes: Array[Byte] = ???

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

  private lazy val data = e.bytes

  lazy val bytes: Array[Byte] = {
    require(proof.hashes.nonEmpty, "Merkle path cannot be empty")
    val dataSize = Ints.toByteArray(data.length)
    val proofLength = Ints.toByteArray(proof.hashes.length)
    val proofSize = Ints.toByteArray(proof.hashes.head.length)
    val proofBytes = proof.hashes.foldLeft(Array.empty: Array[Byte])((b, mp) => b ++ mp)
    dataSize ++ proofLength ++ proofSize ++ data ++ proofBytes
  }

  /**
    * Checks that this block is at position $index in tree with root hash = $rootHash
    */
  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    proof.hashes.reverse.foldLeft(hashFunction.hash(data)) { (x, y) =>
      hashFunction.hash(x, y)
    }.sameElements(rootHash)
  }

}


object SLProof {
  def decode[HashFunction <: CryptographicHash](bytes: Array[Byte]): Try[SLExistenceProof] = Try {
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
      "data" -> JsString(Base58.encode(ts.data)),
      "merklePath" -> JsArray(
        ts.proof.hashes.map(digest => JsString(Base58.encode(digest)))
      )
    ))
  }
}