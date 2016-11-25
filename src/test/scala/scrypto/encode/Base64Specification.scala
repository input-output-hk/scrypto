package scrypto.crypto.encode

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}

class Base64Specification extends PropSpec
with PropertyChecks
with GeneratorDrivenPropertyChecks
with Matchers {


  property("Base64 encoding then decoding preserves data") {
    forAll { data: Array[Byte] =>
      whenever(data.length > 0 && data.head != 0) {
        val encoded = Base64.encode(data)
        val restored = Base64.decode(encoded)
        restored shouldBe data
      }
    }
  }
}
