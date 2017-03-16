package scorex.crypto.authds.legacy.treap

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch.InsertOrUpdate
import scorex.crypto.authds.legacy.treap.Constants._
import scorex.crypto.hash.Blake2b256Unsafe


class TreapSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TwoPartyTests {


  def validKey(key: TreapKey): Boolean = key.length > 1 && key.length < MaxKeySize

  property("skiplist stream") {
    val wt = new Treap()(new Blake2b256Unsafe, Level.skiplistLevel)
    var digest = wt.rootHash()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val a = Append(key, value)
        val proof: TreapModifyProof = wt.modify(a).get
        digest = proof.verify(digest, a).get
      }
    }
  }

  property("Treap stream") {
    val wt = new Treap()
    var digest = wt.rootHash()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val a = Append(key, value)
        val proof: TreapModifyProof = wt.modify(a).get
        digest = proof.verify(digest, a).get
      }
    }
  }

  property("Treap insert one") {
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val wt = new Treap()
        val digest = wt.rootHash()
        val rewrite = InsertOrUpdate(key, value)
        val proof: TreapModifyProof = wt.modify(rewrite).get
        proof.verify(digest, rewrite).get shouldEqual wt.rootHash()
      }
    }
  }

  property("Treap insert") {
    val wt = new Treap()
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val digest = wt.rootHash()
        val rewrite = InsertOrUpdate(key, value)
        val proof: TreapModifyProof = wt.modify(rewrite).get
        proof.verify(digest, rewrite).get shouldEqual wt.rootHash()
      }
    }
  }

  property("Treap update") {
    val wt = new Treap()
    forAll { (key: Array[Byte], value: Array[Byte], value2: Array[Byte]) =>
      whenever(validKey(key) && !(value sameElements value2)) {
        val digest1 = wt.rootHash()
        val a = Append(key, value)
        val proof: TreapModifyProof = wt.modify(a).get
        proof.verify(digest1, a).get shouldEqual wt.rootHash()

        val digest2 = wt.rootHash()
        val a2 = Append(key, value2)
        val updateProof = wt.modify(a2).get
        updateProof.verify(digest2, a2).get shouldEqual wt.rootHash()
      }
    }
  }
}
