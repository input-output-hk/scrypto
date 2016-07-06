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

  property("SLExistanceProof serialization") {
    elements.foreach { e =>
      val proof = sl.elementProof(e)
      proof.isDefined shouldBe true
      proof.check(sl.rootHash) shouldBe true

      val decoded = SLProof.decode(proof.bytes)
      decoded.isSuccess shouldBe true
      decoded.get.isDefined shouldBe true
    }
  }

}
