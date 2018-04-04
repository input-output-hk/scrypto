package scorex.crypto.authds.legacy.treap

import org.scalacheck.Gen
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds._
import scorex.crypto.authds.avltree.batch.InsertOrUpdate
import scorex.crypto.authds.legacy.treap.Constants._
import scorex.crypto.hash.Blake2b256


class TreapSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TwoPartyTests {


  def validKey(key: ADKey): Boolean = key.length > 1 && key.length < MaxKeySize

  def keyValue2Gen: Gen[(ADKey, ADValue, ADValue)] = for {
    key <- genBoundedBytes(1, MaxKeySize)
    value <- genBoundedBytes(1, MaxKeySize)
    value2 <- genBoundedBytes(1, MaxKeySize)
  } yield (ADKey @@ key, ADValue @@ value, ADValue @@ value2)

  def keyValueGen: Gen[(ADKey, ADValue)] = keyValue2Gen.map(a => (a._1, a._2))

  property("skiplist stream") {
    val wt = new Treap()(Blake2b256, Level.skiplistLevel)
    var digest = wt.rootHash()
    forAll(keyValueGen) { case (key: ADKey, value: ADValue) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val a = Append(key, value)
        val proof: TreapModifyProof = wt.run(a).get
        digest = proof.verify(digest, a).get
      }
    }
  }

  property("Treap stream") {
    val wt = new Treap()
    var digest = wt.rootHash()
    forAll(keyValueGen) { case (key: ADKey, value: ADValue) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val a = Append(key, value)
        val proof: TreapModifyProof = wt.run(a).get
        digest = proof.verify(digest, a).get
      }
    }
  }

  property("Treap insert one") {
    forAll(keyValueGen) { case (key: ADKey, value: ADValue) =>
      whenever(validKey(key) && value.nonEmpty) {
        val wt = new Treap()
        val digest = wt.rootHash()
        val rewrite = InsertOrUpdate(key, value)
        val proof: TreapModifyProof = wt.run(rewrite).get
        proof.verify(digest, rewrite).get shouldEqual wt.rootHash()
      }
    }
  }

  property("Treap insert") {
    val wt = new Treap()
    forAll(keyValueGen) { case (key: ADKey, value: ADValue) =>
      whenever(validKey(key) && value.nonEmpty) {
        val digest = wt.rootHash()
        val rewrite = InsertOrUpdate(key, value)
        val proof: TreapModifyProof = wt.run(rewrite).get
        proof.verify(digest, rewrite).get shouldEqual wt.rootHash()
      }
    }
  }

  property("Treap update") {
    val wt = new Treap()
    forAll(keyValue2Gen) { case (key: ADKey, value: ADValue, value2: ADValue) =>
      whenever(validKey(key) && !(value sameElements value2)) {
        val digest1 = wt.rootHash()
        val a = Append(key, value)
        val proof: TreapModifyProof = wt.run(a).get
        proof.verify(digest1, a).get shouldEqual wt.rootHash()

        val digest2 = wt.rootHash()
        val a2 = Append(key, value2)
        val updateProof = wt.run(a2).get
        updateProof.verify(digest2, a2).get shouldEqual wt.rootHash()
      }
    }
  }
}
