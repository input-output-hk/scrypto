package scorex.crypto.authds.merkle.sparse

import scorex.crypto.authds.LeafData
import scorex.crypto.hash.{CryptographicHash, Digest32, Blake2b256Unsafe}
import scorex.utils.Longs

object OpsBenchmark extends App {
  implicit val hf: CryptographicHash[Digest32] = new Blake2b256Unsafe
  val height: Byte = 50
  var tree = SparseMerkleTree.emptyTree(height)
  //bootstrapping
  val bSize = 10000
  var proof: SparseMerkleProof[Digest32] = null
  val tb0 = System.currentTimeMillis()
  (0 until bSize).foreach { i =>
    if (i == bSize / 2) proof = tree.lastProof
    val proofsToUpdate = if (i >= bSize / 2) {
      Seq(proof)
    } else Seq.empty[SparseMerkleProof[Digest32]]
    if (i % 1000 == 0) println(s"$i elements added")
    val (t:  SparseMerkleTree[Digest32], p: Seq[SparseMerkleProof[Digest32]]) =
      tree.update(tree.lastProof, Some(LeafData @@ Longs.toByteArray(i)), proofsToUpdate).get
    tree = t
    if (i >= bSize / 2) proof = p.head
  }
  val tb = System.currentTimeMillis()
  println(s"bootstrapping time: ${tb - tb0}")
  val tv0 = System.currentTimeMillis()
  (1 to 1000).foreach(i => proof.valid(tree))
  val tv = System.currentTimeMillis()
  println(s"1000 updates time: ${tv - tv0} ms")
  val te0 = System.currentTimeMillis()
  (1 to 1000).foreach(_ =>
    tree.update(tree.lastProof, Some(LeafData @@ Longs.toByteArray(2)), Seq())
  )
  val te = System.currentTimeMillis()
  val tp0 = System.currentTimeMillis()
  (1 to 1000).foreach(_ =>
    tree.update(tree.lastProof, Some(LeafData @@ Longs.toByteArray(2)), Seq(proof))
  )
  val tp = System.currentTimeMillis()
  val tu = (tp - tp0) - (te - te0)
  println("1000 proof updates: " + tu)
}
