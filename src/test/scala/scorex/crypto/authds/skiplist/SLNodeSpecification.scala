package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}

class SLNodeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  property("SLNode serialization") {
    forAll(slnodeGenerator) { sn: SLNode =>
      SLNode.parseBytes(sn.bytes)

    }
  }


}
