package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class SLProofSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)
  implicit val hf: CommutativeHash[Blake2b256.type] = CommutativeHash(Blake2b256)
  val sl = new SkipList()(storage, hf)
  val elements = genEl(100)
  val nonIncludedElements = genEl(101).diff(elements)
  sl.update(SkipListUpdate(toDelete = Seq(), toInsert = elements))

  property("SLExistenceProof serialization") {
    elements.foreach { e =>
      proofCheck(e, defined = true)
    }
  }


  property("SLNoneExistanceProof serialization") {
    nonIncludedElements.foreach { e =>
      proofCheck(e, defined = false)
    }
  }

  def proofCheck(e: SLElement, defined: Boolean): Unit = {
    val proof = sl.elementProof(e)
    proof.isDefined shouldBe defined
    proof.check(sl.rootHash) shouldBe true

    val decoded = SLProof.decode(proof.bytes).get
    decoded.isDefined shouldBe defined
    decoded.check(sl.rootHash) shouldBe true

    decoded.bytes shouldEqual proof.bytes
  }


}
