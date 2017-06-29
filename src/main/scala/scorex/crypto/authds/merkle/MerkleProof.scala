package scorex.crypto.authds.merkle

import scorex.crypto.encode.Base58

case class MerkleProof(leaf: Leaf, hashes: Seq[Array[Byte]]) {
  private val hf = leaf.hf
  lazy val rootHash = hashes.foldLeft(leaf.hash) { (a, b) =>
    hf.prefixedHash(1.toByte, a, b)
  }

  override def toString: String = s"MerkleProof($leaf, ${hashes.map(h => Base58.encode(h))})"
}


