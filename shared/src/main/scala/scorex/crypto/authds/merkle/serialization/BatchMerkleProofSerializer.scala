package scorex.crypto.authds.merkle.serialization

import scorex.utils.{Bytes, Ints}
import scorex.crypto.authds.merkle.BatchMerkleProof
import scorex.crypto.authds._
import scorex.crypto.hash._

import scala.util.Try

class BatchMerkleProofSerializer[D <: Digest32, HF <: CryptographicHash[D]](implicit val hf: HF)  {

  private val digestSize = hf.DigestSize
  private val indexSize = 4
  private val sideSize = 1
  private val indicesSize = digestSize + indexSize
  private val proofsSize = digestSize + sideSize

  def serialize(bmp: BatchMerkleProof[D]): Array[Byte] =
    Bytes.concat(
      Ints.toByteArray(bmp.indices.size),
      Ints.toByteArray(bmp.proofs.size),
      indicesToBytes(bmp.indices),
      proofsToBytes(bmp.proofs)
    )

  def deserialize(bytes: Array[Byte]): Try[BatchMerkleProof[D]] = Try {

    if (bytes.length < 8) {
      throw new Error("Deserialization error, empty input.")
    }

    val numIndices = Ints.fromByteArray(bytes.slice(0, 4))
    val numProofs = Ints.fromByteArray(bytes.slice(4, 8))
    val (indices, proofs) = bytes.drop(8).splitAt(numIndices * indicesSize)

    if (indices.length != numIndices * indicesSize || proofs.length != numProofs * proofsSize) {
      throw new Error("Deserialization error, invalid input.")
    }

    BatchMerkleProof(
      indicesFromBytes(indices),
      proofsFromBytes(proofs)
    )
  }

  private[serialization] def indicesToBytes(indices: Seq[(Int, Digest)]): Array[Byte] = {
    Bytes.concat(
      indices.map(i => (Ints.toByteArray(i._1), i._2)).flatten{case (a, b) => Bytes.concat(a, b)}.toArray
    )
  }

  private[serialization] def proofsToBytes(proofs: Seq[(Digest, Side)]): Array[Byte] = {
    Bytes.concat(
      proofs.map(p => (p._1, Array(p._2.toByte))).flatten{
        case (a, b) if a.value.isEmpty => Bytes.concat(Array.ofDim[Byte](32), b)
        case (a, b) => Bytes.concat(a, b)
      }.toArray
    )
  }

  private[serialization] def indicesFromBytes(bytes: Array[Byte]): Seq[(Int, Digest)] = {
    bytes.grouped(indicesSize)
      .map(b => {
        val index = Ints.fromByteArray(b.slice(0, indexSize))
        val hash = b.slice(indexSize, indicesSize).asInstanceOf[Digest]
        (index,hash)
      })
      .toSeq
  }

  private[serialization] def proofsFromBytes(bytes: Array[Byte]): Seq[(Digest, Side)] = {
    bytes.grouped(proofsSize)
      .map(b => {
        val hashBytes = b.slice(0, digestSize)
        val hash = (if (hashBytes.forall(0.toByte.equals)) EmptyByteArray else hashBytes).asInstanceOf[Digest]
        val side = b.apply(digestSize).asInstanceOf[Side]
        (hash, side)
      })
      .toSeq
  }
}