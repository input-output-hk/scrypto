package scorex.crypto.authds.skiplist

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class ExtendedSLProofSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)
  implicit val hf: CommutativeHash[Blake2b256.type] = new CommutativeHash(Blake2b256)
  val sl = new SkipList()(storage, hf)


  property("One by one update and insert") {
    forAll(Gen.choose(1, 10), Arbitrary.arbitrary[Int], Arbitrary.arbitrary[Int]) { (i: Int, seed: Int, seed2: Int) =>
      val toInsert = genEl(i, Some(seed))
      val height = sl.topNode.level
      sl.update(SkipListUpdate(toInsert = toInsert))

      val rootHash = sl.rootHash
      val toUpdate = toInsert.map(e => updatedElement(e))

      val toInsertWith = genEl(i, Some(seed2))
      whenever(toInsertWith.forall(e => !sl.contains(e))) {
        val proofSeq = sl.update(SkipListUpdate(toUpdate = toUpdate), withProofs = true)
        proofSeq.proofs.size shouldEqual toInsert.size
        proofSeq.check(rootHash, sl.rootHash) shouldBe true
      }
    }
  }

  property("ExtendedSLProof serialization") {
    forAll(slelementGenerator) { e: NormalSLElement =>
      whenever(!sl.contains(e)) {
        proofSerializationCheck(e, defined = false)
        sl.insert(e)
        proofSerializationCheck(e, defined = true)
      }
    }
  }

  property("Insert 1 element") {
    forAll(slelementGenerator) { e: NormalSLElement =>
      whenever(!sl.contains(e)) {
        val proofsForUpdate = Seq(ProofToRecalculate(e, sl.extendedElementProof(e)))
        proofsForUpdate.head.proof.isEmpty shouldBe true

        val recalculatedHash = ExtendedSLProof.recalculate(proofsForUpdate, sl.topNode.level)
        sl.insert(e)
        recalculatedHash shouldEqual sl.rootHash
      }
    }
  }

  property("Update elements") {
    forAll(Gen.choose(1, 10)) { i: Int =>
      val forUpdate = genEl(i)
      sl.update(SkipListUpdate(toDelete = Seq(), toInsert = forUpdate))

      val proofsForUpdate = forUpdate map { e =>
        val proof = sl.extendedElementProof(e)
        proof.check(sl.rootHash) shouldBe true
        ProofToRecalculate(updatedElement(e), proof)
      }
      val oldRH = sl.rootHash

      proofsForUpdate.foreach(p => sl.updateOne(p.newEl))

      val recalculatedHash = ExtendedSLProof.recalculate(proofsForUpdate, sl.topNode.level)
      oldRH should not equal sl.rootHash
      recalculatedHash shouldEqual sl.rootHash
    }
  }

  property("SLProofSeq serialization") {
    forAll(Gen.choose(1, 10), Arbitrary.arbitrary[Int]) { (i: Int, seed: Int) =>
      val elements = genEl(i, Some(seed))
      val p = sl.update(SkipListUpdate(toInsert = elements), withProofs = true)
      val decoded = SLProofSeq.parseBytes(p.bytes).get

      decoded.bytes shouldEqual p.bytes
    }
  }


  //TODO fix
  /*
    property("Insert elements") {
      forAll(Gen.choose(2, 2), Gen.choose(100, 1000)) { (i: Int, j: Int) =>
        val toInsert = genEl(i)
        val ch = sl.topNode.level
        toInsert.foreach(e => sl.contains(e) shouldBe false)

        val proofsForUpdate = toInsert.map(e => ProofToRecalculate(e, sl.extendedElementProof(e)))

        val sorted = if (toInsert.head > toInsert.last) toInsert else toInsert.reverse
        sl.insert(sorted.head)
        sl.insert(sorted.last)


        val recalculatedHash = ExtendedSLProof.recalculate(proofsForUpdate, ch)
        recalculatedHash shouldEqual sl.rootHash
      }
    }

    property("Insert 1 and update 1 element") {
      forAll(slelementGenerator) { e: NormalSLElement =>
        whenever(!sl.contains(e)) {
          val forUpdate = genEl(1)
          sl.update(SkipListUpdate(toDelete = Seq(), toInsert = forUpdate))
          val proof = ProofToRecalculate(updatedElement(forUpdate.head), sl.extendedElementProof(forUpdate.head))

          val proofsForUpdate = Seq(ProofToRecalculate(e, sl.extendedElementProof(e)), proof)
          proofsForUpdate.head.proof.isEmpty shouldBe true

          val recalculatedHash = ExtendedSLProof.recalculate(proofsForUpdate, sl.topNode.level)
          sl.insert(e)
          recalculatedHash shouldEqual sl.rootHash
        }
      }
    }
  */


  def proofSerializationCheck(e: SLElement, defined: Boolean): Unit = {
    val proof = sl.extendedElementProof(e)
    proof.isDefined shouldBe defined
    proof.check(sl.rootHash) shouldBe true

    val decoded = ExtendedSLProof.parseBytes(proof.bytes).get
    decoded.isDefined shouldBe defined
    decoded.check(sl.rootHash) shouldBe true
    decoded.l.proof.levHashes foreach { lh =>
      val sameLevHash = proof.l.proof.levHashes.find(_.h sameElements lh.h).get
      sameLevHash.l shouldBe lh.l
      sameLevHash.d shouldBe lh.d
    }

    decoded.bytes shouldEqual proof.bytes
  }

}
