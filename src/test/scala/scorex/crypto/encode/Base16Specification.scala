package scorex.crypto.encode

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}

class Base16Specification extends PropSpec
with PropertyChecks
with GeneratorDrivenPropertyChecks
with Matchers {


  property("Base16 encoding then decoding preserves data") {
    forAll { data: Array[Byte] =>
      whenever(data.length > 0 && data.head != 0) {
        val encoded = Base16.encode(data)
        val restored = Base16.decode(encoded)
        restored shouldBe data
      }
    }
  }
}
