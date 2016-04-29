package scorex.crypto.authds.merkle.versioned

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.merkle.CommonTreeFunctionality


class VersionedMerkleSpecification
  extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers
  with CommonTreeFunctionality {

  property("appends are commutative") {
    for (blocksNum <- List(7, 8, 9, 128)) {

    }
  }

}
