package scorex.crypto.authds.merkle.serialization

import com.google.common.primitives.{Bytes, Ints}
import scorex.crypto.authds.{EmptyByteArray, Side}
import scorex.crypto.hash.Digest

class BatchMerkleProofSerialization[D <: Digest]  {

  def indicesToBytes(indices: Seq[(Int, Digest)]): Array[Byte] = {
    Bytes.concat(
      indices.map(i => (Ints.toByteArray(i._1), i._2)).flatten{case (a, b) => Bytes.concat(a, b)}.toArray
    )
  }

  def proofsToBytes(proofs: Seq[(Digest, Side)]): Array[Byte] = {
    Bytes.concat(
      proofs.map(p => (p._1, Array(p._2.toByte))).flatten{
        case (a, b) if a.isEmpty => Bytes.concat(Array.ofDim[Byte](32), b)
        case (a, b) => Bytes.concat(a, b)
      }.toArray
    )
  }

  def indicesFromBytes(bytes: Array[Byte]): Seq[(Int, Digest)] = {
    bytes.grouped(36)
      .map(b => {
        val index = Ints.fromByteArray(b.slice(0, 4))
        val hash = b.slice(4,36).asInstanceOf[Digest]
        (index,hash)
      })
      .toSeq
  }

  def proofsFromBytes(bytes: Array[Byte]): Seq[(Digest, Side)] = {
    bytes.grouped(33)
      .map(b => {
        val hashBytes = b.slice(0,32)
        val hash = (if (hashBytes.forall(0.toByte.equals)) EmptyByteArray else hashBytes).asInstanceOf[Digest]
        val side = b.apply(32).asInstanceOf[Side]
        (hash, side)
      })
      .toSeq
  }
}