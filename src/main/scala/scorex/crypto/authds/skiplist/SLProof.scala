package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import play.api.libs.json._
import scorex.crypto.authds.AuthData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.util.Try

sealed trait SLProof extends AuthData[SLPath] {
  type Digest = CryptographicHash#Digest
  val data: Array[Byte]
  val proof: SLPath
  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean

  lazy val bytes: Array[Byte] = {
    require(proof.hashes.nonEmpty, "Merkle path cannot be empty")
    val dataSize = Ints.toByteArray(this.data.length)
    val proofLength = Ints.toByteArray(proof.hashes.length)
    val proofSize = Ints.toByteArray(proof.hashes.head.length)
    val proofBytes = proof.hashes.foldLeft(Array.empty: Array[Byte])((b, mp) => b ++ mp)
    dataSize ++ proofLength ++ proofSize ++ data ++ proofBytes
  }

}

case class SLNonExistenceProof(data: Array[Byte], proof: SLPath) extends SLProof {
  ???

  override def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    proof.hashes.reverse.foldLeft(hashFunction.hash(data)) { (x, y) =>
      hashFunction.hash(x, y)
    }.sameElements(rootHash)
  }
}

/**
  * @param data - data block
  * @param proof - skiplist path, complementary to data block
  */
case class SLExistenceProof(data: Array[Byte], proof: SLPath) extends SLProof {

  /**
    * Checks that this block is at position $index in tree with root hash = $rootHash
    */
  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    proof.hashes.reverse.foldLeft(hashFunction.hash(data)) { (x, y) =>
      hashFunction.hash(x, y)
    }.sameElements(rootHash)
  }

}

object SLExistenceProof {
  def decode[HashFunction <: CryptographicHash](bytes: Array[Byte]): Try[SLExistenceProof] = Try {
    val dataSize = Ints.fromByteArray(bytes.slice(0, 4))
    val merklePathLength = Ints.fromByteArray(bytes.slice(4, 8))
    val merklePathSize = Ints.fromByteArray(bytes.slice(8, 12))
    val data = bytes.slice(12, 12 + dataSize)
    val merklePathStart = 12 + dataSize
    val merklePath = (0 until merklePathLength).map { i =>
      bytes.slice(merklePathStart + i * merklePathSize, merklePathStart + (i + 1) * merklePathSize)
    }
    SLExistenceProof(data, SLPath(merklePath))
  }

  implicit def authDataBlockReads[T, HashFunction <: CryptographicHash]
  (implicit fmt: Reads[T]): Reads[SLExistenceProof] = new Reads[SLExistenceProof] {
    def reads(json: JsValue): JsResult[SLExistenceProof] = JsSuccess(SLExistenceProof(
      Base58.decode((json \ "data").as[String]).get,
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