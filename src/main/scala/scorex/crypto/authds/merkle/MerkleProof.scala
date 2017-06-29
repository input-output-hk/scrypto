package scorex.crypto.authds.merkle

case class MerkleProof(leaf: Leaf, hashes: Seq[Array[Byte]]) {
  private val hf = leaf.hf
  lazy val rootHash = hashes.foldLeft(leaf.hash) { (a, b) =>
    hf.prefixedHash(1.toByte, a, b)
  }
}


