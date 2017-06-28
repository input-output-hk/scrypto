package scorex.crypto.authds.merkle

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.hash.Blake2b256Unsafe

class MerkleTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers {
  implicit val hf = new Blake2b256Unsafe

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
