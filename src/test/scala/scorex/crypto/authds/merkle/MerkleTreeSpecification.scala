package scorex.crypto.authds.merkle

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.hash.Blake2b256Unsafe

class MerkleTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {
  implicit val hf = new Blake2b256Unsafe


  property("Proof generation by index") {
    forAll(smallInt) { N: Int =>
      whenever(N > 0) {
        val d = (0 until N).map(_ => scorex.utils.Random.randomBytes(32))
        val tree = MerkleTree(d)
        tree.rootHash
        (0 until N).foreach { i =>
          assert(tree.proofByIndex(i).get.leaf.data sameElements d(i))
        }
        (N until N + 100).foreach { i =>
          assert(tree.proofByIndex(i).isEmpty)
        }
      }
    }
  }

  property("Tree creation from 1 element") {
    forAll { d: Array[Byte] =>
      val tree = MerkleTree(Seq(d))(hf)
      val leaf = Leaf(d)
      tree.rootHash shouldEqual hf.prefixedHash(0: Byte, d)
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
