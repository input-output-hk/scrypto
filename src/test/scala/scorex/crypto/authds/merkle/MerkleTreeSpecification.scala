package scorex.crypto.authds.merkle

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class MerkleTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {
  implicit val hf = Blake2b256

  property("Proof generation by element") {
    forAll(smallInt) { N: Int =>
      whenever(N > 0) {
        val d = (0 until N).map(_ => scorex.utils.Random.randomBytes(32))
        val leafs = d.map(data => Leaf(data))
        val tree = MerkleTree(d)
        leafs.foreach { l =>
          val proof = tree.proofByElement(l).get
          proof.leafData.sameElements(l.data) shouldBe true
          proof.valid(tree.rootHash) shouldBe true
        }
      }
    }

  }

  property("Proof generation by index") {
    forAll(smallInt) { N: Int =>
      whenever(N > 0) {
        val d = (0 until N).map(_ => scorex.utils.Random.randomBytes(32))
        val tree = MerkleTree(d)
        (0 until N).foreach { i =>
          tree.proofByIndex(i).get.leafData shouldEqual d(i)
          tree.proofByIndex(i).get.valid(tree.rootHash) shouldBe true
        }
        (N until N + 100).foreach { i =>
          tree.proofByIndex(i).isEmpty shouldBe true
        }
      }
    }
  }

  property("Tree creation from 1 element") {
    forAll { d: Array[Byte] =>
      whenever(d.length > 0) {
        val tree = MerkleTree(Seq(d))(hf)
        tree.rootHash shouldEqual hf.prefixedHash(1: Byte, hf.prefixedHash(0: Byte, d), Array())
      }
    }
  }

  property("Tree creation from 2 element") {
    forAll { (d1: Array[Byte], d2: Array[Byte]) =>
      val tree = MerkleTree(Seq(d1, d2))(hf)
      tree.rootHash shouldEqual hf.prefixedHash(1: Byte, hf.prefixedHash(0: Byte, d1), hf.prefixedHash(0: Byte, d2))
    }
  }

  property("Tree creation from a lot of elements") {
    forAll { d: Seq[Array[Byte]] =>
      whenever(d.nonEmpty) {
        val tree = MerkleTree(d)
        tree.rootHash
      }
    }
  }
}
