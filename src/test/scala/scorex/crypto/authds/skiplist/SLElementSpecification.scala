package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage

class SLElementSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {
  implicit val storage = new MvStoreBlobBlobStorage(None)

  property("SLElement creation") {
    forAll(slelementGenerator) { se: SLElement =>
      se < MaxSLElement shouldBe true
      se > MinSLElement shouldBe true
    }
  }

  property("SLElement compare") {
    forAll(slelementGenerator, slelementGenerator) { (se1: SLElement, se2: SLElement) =>
      whenever(!(se1.key sameElements se2.key)) {
        se1.compare(se2) should not be 0
        se1 == se2 shouldBe false
      }
    }

  }

  property("SLElement serialization") {
    forAll(slelementGenerator) { se: SLElement =>
      SLElement.parseBytes(se.bytes).get.compare(se) shouldBe 0
      SLElement.parseBytes(se.bytes).get == se shouldBe true
    }
    SLElement.parseBytes(MinSLElement.bytes).get.compare(MinSLElement) shouldBe 0
    SLElement.parseBytes(MaxSLElement.bytes).get.compare(MaxSLElement) shouldBe 0
  }


}
