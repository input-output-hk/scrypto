package scorex.crypto.authds.skiplist

import org.scalacheck.Gen
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class ExtendedSLProofSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)
  implicit val hf: CommutativeHash[Blake2b256.type] = new CommutativeHash(Blake2b256)
  val sl = new SkipList()(storage, hf)
  val elements = genEl(21, Some(11))
  sl.update(SkipListUpdate(toDelete = Seq(), toInsert = elements))

  property("ExtendedSLProof serialization") {
    forAll(slelementGenerator) { e: NormalSLElement =>
      whenever(!sl.contains(e)) {
        proofSerializationCheck(e, defined = false)
        sl.insert(e)
        proofSerializationCheck(e, defined = true)
      }
    }
  }

  def proofSerializationCheck(e: SLElement, defined: Boolean): Unit = {
    val proof = sl.elementProof(e)
    proof.isDefined shouldBe defined
    proof.check(sl.rootHash) shouldBe true

    val decoded = SLProof.decode(proof.bytes).get
    decoded.isDefined shouldBe defined
    decoded.check(sl.rootHash) shouldBe true

    decoded.bytes shouldEqual proof.bytes
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

      proofsForUpdate.foreach(p => sl.update(p.newEl))

      val recalculatedHash = ExtendedSLProof.recalculate(proofsForUpdate, sl.topNode.level)
      recalculatedHash shouldEqual sl.rootHash
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



  def updatedElement(e: NormalSLElement): NormalSLElement = {
    val newE = e.copy(value = (1: Byte) +: e.value)

    e.key shouldEqual newE.key
    e.value should not equal newE.value
    newE

  }

}
