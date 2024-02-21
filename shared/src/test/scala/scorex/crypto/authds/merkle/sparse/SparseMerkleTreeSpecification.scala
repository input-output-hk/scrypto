package scorex.crypto.authds.merkle.sparse

import scorex.utils.Longs
import org.scalatest.matchers.should.Matchers
import org.scalatest.propspec.AnyPropSpec
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.TestingCommons
import scorex.crypto.authds.LeafData
import scorex.crypto.hash.{CryptographicHash, Digest32, Blake2b256}

class SparseMerkleTreeSpecification extends AnyPropSpec with ScalaCheckDrivenPropertyChecks with Matchers with TestingCommons {

  implicit val hf: CryptographicHash[Digest32] = Blake2b256

  property("Tree has valid last proof") {
    forAll { (height: Byte) =>
      whenever(height > 0) {
        val tree0 = SparseMerkleTree.emptyTree(height)
        tree0.lastProof.valid(tree0.rootDigest, height) shouldBe true
      }
    }
  }

  property("ZeroProof tree has valid proof") {
    forAll { (height: Byte) =>
      whenever(height > 0) {
        val zp = SparseMerkleTree.zeroProof[Digest32](height)
        val zp1 = zp.copy(idx = 1)
        val tree0 = SparseMerkleTree.emptyTree(height)

        zp.valid(tree0.rootDigest, height) shouldBe true
        zp1.valid(tree0.rootDigest, height) shouldBe true
      }
    }
  }

  property("Updated tree has valid proof") {
    forAll { (height: Byte) =>
      whenever(height > 1) {
        val zp = SparseMerkleTree.zeroProof[Digest32](height)
        val tree0 = SparseMerkleTree.emptyTree(height)
        val newLeafData = Some(LeafData @@ Longs.toByteArray(5))
        val (tree1, updProofs) = tree0.update(zp, newLeafData, Seq(zp)).get

        updProofs.head.valid(tree1.rootDigest, height) shouldBe true
        tree1.lastProof.valid(tree1.rootDigest, height) shouldBe true

        val newLeafData10 = Some(LeafData @@ Longs.toByteArray(10))
        val tree2 = tree1.update(tree1.lastProof, newLeafData10).get._1
        tree2.lastProof.valid(tree2.rootDigest, height) shouldBe true
      }
    }
  }
}
