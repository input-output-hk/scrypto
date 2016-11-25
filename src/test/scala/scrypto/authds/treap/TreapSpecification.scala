package scrypto.authds.treap

import com.google.common.primitives.Longs
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scrypto.TestingCommons
import scrypto.authds.{TwoPartyTests, Level}
import scrypto.hash.Blake2b256Unsafe

import scala.util.Success


class TreapSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TwoPartyTests {


  def validKey(key: TreapKey): Boolean = key.length > 1 && key.length < MaxKeySize

  property("skiplist stream") {
    val wt = new Treap()(new Blake2b256Unsafe, Level.skiplistLevel)
    var digest = wt.rootHash()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val proof: TreapModifyProof = wt.modify(key, append(value)).get
        digest = proof.verify(digest, append(value)).get
      }
    }
  }

  property("Treap stream") {
    val wt = new Treap()
    var digest = wt.rootHash()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val proof: TreapModifyProof = wt.modify(key, append(value)).get
        digest = proof.verify(digest, append(value)).get
      }
    }
  }

  property("Treap insert one") {
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val wt = new Treap()
        val digest = wt.rootHash()
        val proof: TreapModifyProof = wt.modify(key, rewrite(value)).get
        proof.verify(digest, rewrite(value)).get shouldEqual wt.rootHash()
      }
    }
  }

  property("Treap insert") {
    val wt = new Treap()
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val digest = wt.rootHash()
        val proof: TreapModifyProof = wt.modify(key, rewrite(value)).get
        proof.verify(digest, rewrite(value)).get shouldEqual wt.rootHash()
      }
    }
  }

  property("Treap update") {
    val wt = new Treap()
    forAll { (key: Array[Byte], value: Array[Byte], value2: Array[Byte]) =>
      whenever(validKey(key) && !(value sameElements value2)) {
        val digest1 = wt.rootHash()
        val proof: TreapModifyProof = wt.modify(key, append(value)).get
        proof.verify(digest1, append(value)).get shouldEqual wt.rootHash()

        val digest2 = wt.rootHash()
        val updateProof = wt.modify(key, append(value2)).get
        updateProof.verify(digest2, append(value2)).get shouldEqual wt.rootHash()
      }
    }
  }

}
