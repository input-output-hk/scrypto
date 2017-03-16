package scorex.crypto.authds.avltree

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch.{Insert, InsertOrUpdate, Update}
import scorex.crypto.authds.legacy.avltree.{AVLModifyProof, AVLTree}
import scorex.crypto.hash.Sha256
import scorex.utils.Random

class AVLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val KL = 26
  val VL = 8

  /*
  todo: uncomment & fix
  property("lookup") {
    val tree = new AVLTree(KL)
    var digest: Label = tree.rootHash()

    forAll(kvGen) { case (aKey2, aValue) =>
      val aKey = Random.randomBytes(KL)
      digest shouldEqual tree.rootHash()

      tree.lookup(aKey).get.verifyLookup(digest, existence = false).get shouldEqual digest
      tree.lookup(aKey).get.verifyLookup(digest, existence = true) shouldBe None

      digest shouldEqual tree.rootHash()
      val proof = tree.modify(aKey, replaceLong(aValue)).get
      digest = proof.verify(digest, replaceLong(aValue)).get

      tree.lookup(aKey).get.verifyLookup(digest, existence = true).get shouldEqual digest
      tree.lookup(aKey).get.verifyLookup(digest, existence = false) shouldBe None
    }
  }*/

  property("Failure in update function") {
    val tree = new AVLTree(KL)
    var digest = tree.rootHash()

    forAll(kvGen) { case (aKey, aValue) =>
      digest shouldEqual tree.rootHash()

      tree.modify(Update(aKey, aValue)).isFailure shouldBe true
      digest shouldEqual tree.rootHash()

      val i = Insert(aKey, aValue)
      val proof2 = tree.modify(i)
      digest = proof2.get.verify(digest, i).get

      tree.modify(Insert(aKey, aValue)).isFailure shouldBe true
      digest shouldEqual tree.rootHash()

      val u = Update(aKey, aValue)
      val proof4 = tree.modify(u)
      digest = proof4.get.verify(digest, u).get
    }
  }

  property("stream") {
    val wt = new AVLTree(KL)
    var digest = wt.rootHash()
    forAll(kvGen) { case (aKey, aValue) =>
      digest shouldEqual wt.rootHash()

      val rewrite = InsertOrUpdate(aKey, aValue.take(8))
      val proof = wt.modify(rewrite)
      digest = proof.get.verify(digest, rewrite).get
    }
  }

  property("insert") {
    val wt = new AVLTree(KL)
    forAll(kvGen) { case (aKey, aValue) =>
      val digest = wt.rootHash()
      val rewrite = InsertOrUpdate(aKey, aValue)
      val proof = wt.modify(rewrite).get
      proof.verify(digest, rewrite).get shouldEqual wt.rootHash()
    }
  }


  property("update") {
    val wt = new AVLTree(KL)
    forAll(genBoundedBytes(KL, KL), genBoundedBytes(VL, VL), genBoundedBytes(VL, VL)) {
      (key: Array[Byte], value: Array[Byte], value2: Array[Byte]) =>
        whenever(!(value sameElements value2)) {
          val digest1 = wt.rootHash()
          val rewrite1 = InsertOrUpdate(key, value.take(VL))
          val proof = wt.modify(rewrite1).get
          proof.verify(digest1, rewrite1).get shouldEqual wt.rootHash()

          val digest2 = wt.rootHash()
          val rewrite2 = InsertOrUpdate(key, value.take(VL))
          val updateProof = wt.modify(rewrite2).get
          updateProof.verify(digest2, rewrite2).get shouldEqual wt.rootHash()
        }
    }
  }

  property("AVLModifyProof serialization") {
    val wt = new AVLTree(KL)

    genElements(100, 1, 26).foreach(e => wt.modify(genUpd(e)))

    var digest = wt.rootHash()
    forAll(kvGen) { case (aKey, aValue) =>
      whenever(aKey.length == KL && aValue.length == VL) {
        digest shouldEqual wt.rootHash()
        val rewrite = InsertOrUpdate(aKey, aValue.take(VL))
        val proof = wt.modify(rewrite).get
        digest = proof.verify(digest, rewrite).get
        val parsed = AVLModifyProof.parseBytes(proof.bytes)(KL, 32).get

        parsed.key shouldEqual proof.key
        parsed.proofSeq.indices foreach { i =>
          parsed.proofSeq(i).bytes shouldEqual proof.proofSeq(i).bytes
        }
        parsed.bytes shouldEqual proof.bytes

        val value2 = Sha256(aValue)
        val rewrite2 = InsertOrUpdate(aKey, value2.take(VL))
        val digest2 = wt.rootHash()
        val uProof = wt.modify(rewrite2).get
        digest = uProof.verify(digest2, rewrite2).get

        val uParsed = AVLModifyProof.parseBytes(uProof.bytes)(KL, 32).get
        uParsed.bytes shouldEqual uProof.bytes
      }
    }
  }

  def kvGen: Gen[(Array[Byte], Array[Byte])] = for {
    key <- Gen.listOfN(KL, Arbitrary.arbitrary[Byte]).map(_.toArray) suchThat
      (k => !(k sameElements Array.fill(KL)(-1: Byte)) && !(k sameElements Array.fill(KL)(0: Byte)) && k.length == KL)
    value <- Gen.listOfN(VL, Arbitrary.arbitrary[Byte]).map(_.toArray)
  } yield (key, value)
}
