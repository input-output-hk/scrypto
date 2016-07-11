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
  val elements = genEl(100, Some(11))
  sl.update(SkipListUpdate(toDelete = Seq(), toInsert = elements))

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

      val recalculatedHash = ExtendedSLProof.recalculate(proofsForUpdate)
      recalculatedHash shouldEqual sl.rootHash
    }
  }

  property("Insert 1 element") {
    forAll(slelementGenerator) { e: NormalSLElement =>
      whenever(! sl.contains(e)) {
        val proof = sl.extendedElementProof(e)
        ProofToRecalculate(e, proof)
      }
    }
  }


  def updatedElement(e: NormalSLElement): NormalSLElement = {
    val newE = e.copy(value = (1: Byte) +: e.value)

    e.key shouldEqual newE.key
    e.value should not equal newE.value
    newE

  }

}
