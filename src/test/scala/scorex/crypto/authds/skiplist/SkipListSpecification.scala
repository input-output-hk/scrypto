package scorex.crypto.authds.skiplist

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}

class SkipListSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLElementGen {

  val sl = new SkipList

  property("SkipList should contain inserted element") {
    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)){
        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
      }
    }
  }

  property("SkipList should not contain deleted element") {
    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)){
        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
        sl.delete(newSE) shouldBe true
        sl.contains(newSE) shouldBe false
      }
    }
  }


}
