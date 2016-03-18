package scorex.crypto.ads.merkle

import org.scalacheck.Arbitrary
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.utils.Random.randomBytes

class AuthDataBlockSpecification extends PropSpec with PropertyChecks with GeneratorDrivenPropertyChecks with Matchers {

  val keyVal = for {
    key: Long <- Arbitrary.arbitrary[Long]
    value <- Arbitrary.arbitrary[String]
  } yield AuthDataBlock(value.getBytes, MerklePath(key, Seq(randomBytes(), randomBytes())))

  property("decode-encode roundtrip") {
    forAll(keyVal) { case b: AuthDataBlock[_] =>
      val decoded = AuthDataBlock.decode(b.bytes).get
      decoded.data shouldBe b.data
      decoded.merklePathHashes.size shouldBe b.merklePathHashes.size
      decoded.merklePathHashes.head shouldBe b.merklePathHashes.head
      decoded.merklePathHashes(1) shouldBe b.merklePathHashes(1)
    }
  }
}