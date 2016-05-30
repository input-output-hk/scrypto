package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import play.api.libs.json._
import scorex.crypto.authds.AuthData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.util.Try


/**
 * @param data - data block
 * @param proof - segment position and merkle path, complementary to data block
 */
case class SLAuthData(data: Array[Byte], proof: SLPath) extends AuthData[SLPath] {

  type Digest = CryptographicHash#Digest

  lazy val bytes: Array[Byte] = {
    require(this.merklePathHashes.nonEmpty, "Merkle path cannot be empty")
    val dataSize = Ints.toByteArray(this.data.length)
    val merklePathLength = Ints.toByteArray(this.merklePathHashes.length)
    val merklePathSize = Ints.toByteArray(this.merklePathHashes.head.length)
    val merklePathBytes = this.merklePathHashes.foldLeft(Array.empty: Array[Byte])((b, mp) => b ++ mp)
    dataSize ++ merklePathLength ++ merklePathSize ++ data ++ merklePathBytes
  }

  lazy val merklePathHashes = proof.hashes

  /**
   * Checks that this block is at position $index in tree with root hash = $rootHash
   */
  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean = {
    proof.hashes.reverse.foldLeft(data)((x, y) => hashFunction.hash(x, y)).sameElements(rootHash)
  }

}

object SLAuthData {
  def decode[HashFunction <: CryptographicHash](bytes: Array[Byte]): Try[SLAuthData] = Try {
    val dataSize = Ints.fromByteArray(bytes.slice(0, 4))
    val merklePathLength = Ints.fromByteArray(bytes.slice(4, 8))
    val merklePathSize = Ints.fromByteArray(bytes.slice(8, 12))
    val data = bytes.slice(12, 12 + dataSize)
    val merklePathStart = 12 + dataSize
    val merklePath = (0 until merklePathLength).map { i =>
      bytes.slice(merklePathStart + i * merklePathSize, merklePathStart + (i + 1) * merklePathSize)
    }
    SLAuthData(data, SLPath(merklePath))
  }

  implicit def authDataBlockReads[T, HashFunction <: CryptographicHash]
  (implicit fmt: Reads[T]): Reads[SLAuthData] = new Reads[SLAuthData] {
    def reads(json: JsValue): JsResult[SLAuthData] = JsSuccess(SLAuthData(
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

  implicit def authDataBlockWrites[T, HashFunction <: CryptographicHash](implicit fmt: Writes[T]): Writes[SLAuthData]
  = new Writes[SLAuthData] {
    def writes(ts: SLAuthData) = JsObject(Seq(
      "data" -> JsString(Base58.encode(ts.data)),
      "merklePath" -> JsArray(
        ts.merklePathHashes.map(digest => JsString(Base58.encode(digest)))
      )
    ))
  }
}