package scorex.crypto.encode

import java.util

import org.scalacheck.Arbitrary
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}

class Base58Specification extends EncoderSpecification {

  override val encoder: BytesEncoder = Base58

  property("Base58 encoding then decoding for genesis signature") {
    val data = Array.fill(64)(0: Byte)
    val encoded = Base58.encode(data)
    encoded shouldBe "1111111111111111111111111111111111111111111111111111111111111111"
    val restored = Base58.decode(encoded).get
    restored.length shouldBe data.length
    restored shouldBe data
  }

  property("base58 sample") {
    val b58 = "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i"
    Base58.encode(Base58.decode(b58).get) shouldBe b58
  }

  property("Base58 round trip") {
    forAll(Arbitrary.arbString.arbitrary.filter(_.nonEmpty)) { origStr =>
      val origBytes = origStr.getBytes()
      val decodedBytes = Base58.decode(Base58.encode(origBytes)).get
      util.Arrays.equals(origBytes, decodedBytes)
    }
  }
}
