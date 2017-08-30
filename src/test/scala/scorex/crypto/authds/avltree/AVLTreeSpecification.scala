package scorex.crypto.authds.avltree

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.avltree.batch.{Insert, InsertOrUpdate, Lookup, Update}
import scorex.crypto.authds.legacy.avltree.{AVLModifyProof, AVLTree}
import scorex.crypto.authds.{ADKey, ADValue, TwoPartyTests}
import scorex.crypto.hash.Sha256

class AVLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val KL = 26
  val VL = 8

  def kvGen: Gen[(ADKey, ADValue)] = for {
    key <- Gen.listOfN(KL, Arbitrary.arbitrary[Byte]).map(_.toArray) suchThat
      (k => !(k sameElements Array.fill(KL)(-1: Byte)) && !(k sameElements Array.fill(KL)(0: Byte)) && k.length == KL)
    value <- Gen.listOfN(VL, Arbitrary.arbitrary[Byte]).map(_.toArray)
  } yield (ADKey @@ key, ADValue @@ value)


  property("lookup") {
    val tree = new AVLTree(KL)

    forAll(kvGen) { case (ak, aValue) =>
      val aKey = ADKey @@ Sha256(ak).take(KL)

      val l = Lookup(aKey)

      tree.run(Insert(aKey, aValue))

      val rootBefore = tree.rootHash()

      val lookupProof = tree.run(l).get

      val lw = Lookup(ADKey @@ Sha256(aKey).take(KL))
      val lwProof = tree.run(lw).get
      val lwProofDigest = lwProof.verifyLookup(rootBefore, existence = false).get
      lwProof.verifyLookup(rootBefore, existence = true).isEmpty shouldBe true

      val proofDigest = lookupProof.verifyLookup(rootBefore, existence = true).get
      lookupProof.verifyLookup(rootBefore, existence = false).isEmpty shouldBe true

      val rootAfter = tree.rootHash()

      lwProofDigest.sameElements(proofDigest) shouldBe true
      proofDigest.sameElements(rootAfter) shouldBe true
      rootBefore.sameElements(rootAfter) shouldBe true
    }
  }

  property("Failure in update function") {
    val tree = new AVLTree(KL)
    var digest = tree.rootHash()

    forAll(kvGen) { case (aKey, aValue) =>
      digest shouldEqual tree.rootHash()

      tree.run(Update(aKey, aValue)).isFailure shouldBe true
      digest shouldEqual tree.rootHash()

      val i = Insert(aKey, aValue)
      val proof2 = tree.run(i)
      digest = proof2.get.verify(digest, i).get

      tree.run(Insert(aKey, aValue)).isFailure shouldBe true
      digest shouldEqual tree.rootHash()

      val u = Update(aKey, aValue)
      val proof4 = tree.run(u)
      digest = proof4.get.verify(digest, u).get
    }
  }

  property("stream") {
    val wt = new AVLTree(KL)
    var digest = wt.rootHash()
    forAll(kvGen) { case (aKey, aValue) =>
      digest shouldEqual wt.rootHash()

      val rewrite = InsertOrUpdate(aKey, aValue)
      val proof = wt.run(rewrite)
      digest = proof.get.verify(digest, rewrite).get
    }
  }

  property("insert") {
    val wt = new AVLTree(KL)
    forAll(kvGen) { case (aKey, aValue) =>
      val digest = wt.rootHash()
      val rewrite = InsertOrUpdate(aKey, aValue)
      val proof = wt.run(rewrite).get
      proof.verify(digest, rewrite).get shouldEqual wt.rootHash()
    }
  }


  property("update") {
    val wt = new AVLTree(KL)
    forAll(genBoundedBytes(KL, KL), genBoundedBytes(VL, VL), genBoundedBytes(VL, VL)) {
      (key: Array[Byte], value: Array[Byte], value2: Array[Byte]) =>
        whenever(!(value sameElements value2)) {
          val digest1 = wt.rootHash()
          val rewrite1 = InsertOrUpdate(ADKey @@ key, ADValue @@ value.take(VL))
          val proof = wt.run(rewrite1).get
          proof.verify(digest1, rewrite1).get shouldEqual wt.rootHash()

          val digest2 = wt.rootHash()
          val rewrite2 = InsertOrUpdate(ADKey @@ key, ADValue @@ value.take(VL))
          val updateProof = wt.run(rewrite2).get
          updateProof.verify(digest2, rewrite2).get shouldEqual wt.rootHash()
        }
    }
  }

  property("AVLModifyProof serialization") {
    val wt = new AVLTree(KL)

    genElements(100, 1, 26).foreach(e => wt.run(genUpd(ADKey @@ e)))

    var digest = wt.rootHash()
    forAll(kvGen) { case (aKey, aValue) =>
      whenever(aKey.length == KL && aValue.length == VL) {
        digest shouldEqual wt.rootHash()
        val rewrite = InsertOrUpdate(aKey, ADValue @@ aValue.take(VL))
        val proof = wt.run(rewrite).get
        digest = proof.verify(digest, rewrite).get
        val parsed = AVLModifyProof.parseBytes(proof.bytes)(KL, 32).get

        parsed.key shouldEqual proof.key
        parsed.proofSeq.indices foreach { i =>
          parsed.proofSeq(i).bytes shouldEqual proof.proofSeq(i).bytes
        }
        parsed.bytes shouldEqual proof.bytes

        val value2 = Sha256(aValue)
        val rewrite2 = InsertOrUpdate(aKey, ADValue @@ value2.take(VL))
        val digest2 = wt.rootHash()
        val uProof = wt.run(rewrite2).get
        digest = uProof.verify(digest2, rewrite2).get

        val uParsed = AVLModifyProof.parseBytes(uProof.bytes)(KL, 32).get
        uParsed.bytes shouldEqual uProof.bytes
      }
    }
  }
}
