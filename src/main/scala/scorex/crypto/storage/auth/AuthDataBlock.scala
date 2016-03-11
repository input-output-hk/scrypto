package scorex.crypto.storage.auth

import com.google.common.primitives.{Longs, Bytes, Ints}
import play.api.libs.json._
import scorex.crypto.encode.Base58
import scorex.crypto.hash.CryptographicHash
import scorex.crypto.hash.CryptographicHash._

import scala.annotation.tailrec
import scala.util.Try

/**
  * @param data - data block
  * @param signature - segment position and merkle path, complementary to data block
  */
case class AuthDataBlock[Block](data: Block, signature: MerkleProof) {

  val merklePath = signature.merklePath

  /**
    * Checks that this block is at position $index in tree with root hash = $rootHash
    */
  def check[HashImpl <: CryptographicHash](rootHash: Digest)
                                          (hashFunction: HashImpl = DefaultHash): Boolean = {

    @tailrec
    def calculateHash(idx: Position, nodeHash: Digest, path: Seq[Digest]): Digest = {
      val hash = if (idx % 2 == 0) hashFunction(nodeHash ++ path.head) else hashFunction(path.head ++ nodeHash)
      if (path.size == 1) hash else calculateHash(idx / 2, hash, path.tail)
    }

    if (merklePath.nonEmpty)
      calculateHash(signature.index, hashFunction(data.asInstanceOf[Message]), merklePath) sameElements rootHash
    else
      false
  }
}

object AuthDataBlock {

  def encode(b: AuthDataBlock[Array[Byte]]): Array[Byte] = {
    require(b.merklePath.nonEmpty, "Merkle path cannot be empty")
    val dataSize = Bytes.ensureCapacity(Ints.toByteArray(b.data.length), 4, 0)
    val merklePathLength = Bytes.ensureCapacity(Ints.toByteArray(b.merklePath.length), 4, 0)
    val merklePathSize = Bytes.ensureCapacity(Ints.toByteArray(b.merklePath.head.length), 4, 0)
    val merklePath = b.merklePath.foldLeft(Array.empty: Array[Byte])((b, mp) => b ++ mp)
    dataSize ++ merklePathLength ++ merklePathSize ++ b.data ++ merklePath ++ Longs.toByteArray(b.signature.index)
  }

  def decode(bytes: Array[Byte]): Try[AuthDataBlock[Array[Byte]]] = Try {
    val dataSize = Ints.fromByteArray(bytes.slice(0, 4))
    val merklePathLength = Ints.fromByteArray(bytes.slice(4, 8))
    val merklePathSize = Ints.fromByteArray(bytes.slice(8, 12))
    val data = bytes.slice(12, 12 + dataSize)
    val merklePathStart = 12 + dataSize
    val merklePath = (0 until merklePathLength).map { i =>
      bytes.slice(merklePathStart + i * merklePathSize, merklePathStart + (i + 1) * merklePathSize)
    }
    val index = Longs.fromByteArray(bytes.takeRight(8))
    AuthDataBlock(data, MerkleProof(index, merklePath))
  }

  implicit def authDataBlockReads[T](implicit fmt: Reads[T]): Reads[AuthDataBlock[T]] = new Reads[AuthDataBlock[T]] {
    def reads(json: JsValue): JsResult[AuthDataBlock[T]] = JsSuccess(AuthDataBlock[T](
      Base58.decode((json \ "data").as[String]).get.asInstanceOf[T],
      MerkleProof(
        (json \ "index").as[Long],
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

  implicit def authDataBlockWrites[T](implicit fmt: Writes[T]): Writes[AuthDataBlock[T]] = new Writes[AuthDataBlock[T]] {
    def writes(ts: AuthDataBlock[T]) = JsObject(Seq(
      "data" -> JsString(Base58.encode(ts.data.asInstanceOf[Array[Byte]])),
      "index" -> JsNumber(ts.signature.index),
      "merklePath" -> JsArray(
        ts.merklePath.map(digest => JsString(Base58.encode(digest)))
      )
    ))
  }
}