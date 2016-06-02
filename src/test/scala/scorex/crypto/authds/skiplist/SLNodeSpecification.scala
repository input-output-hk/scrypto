package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage

class SLNodeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)

  property("SLNode serialization") {
    forAll(slnodeGenerator) { sn: SLNode =>
      SLNode.parseBytes(sn.bytes).isSuccess shouldBe true
    }
  }


}
