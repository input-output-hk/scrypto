package scorex.crypto.authds.skiplist

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}

class SLElementSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLElementGen {

  property("SLElement creation") {
    forAll(slelementGenerator) { se: SLElement =>
      se < MaxSLElement shouldBe true
      se > MinSLElement shouldBe true
    }

  }


}
