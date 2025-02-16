package scorex.crypto.hash

import org.scalatest.matchers.should.Matchers
import org.scalatest.propspec.AnyPropSpec
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class Blake2bUnsafeSpecification extends AnyPropSpec
with ScalaCheckDrivenPropertyChecks
with Matchers {

  val unsafeHash = new Blake2b256Unsafe

  property("Unsafe should produce the same result") {
    forAll { (message: Array[Byte]) =>
      unsafeHash.hash(message) shouldEqual Blake2b256(message)
    }
  }

  property("Unsafe should produce the same result for multiple inputs") {
    forAll { (part1: Array[Byte], part2: Array[Byte]) =>
      unsafeHash.hash(part1, part2) shouldEqual Blake2b256(part1 ++ part2)
    }
  }


}

