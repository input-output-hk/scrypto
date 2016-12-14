package scorex.crypto.hash

import scorex.crypto.utils.HashHelpers.hashChain

class HashChainSpecification extends HashTest {

  val ch = hashChain(Blake256, Sha256, CubeHash256)

  property(s"chain apply hashes sequentially") {
    forAll { data: Array[Byte] =>
      ch.hash(data) shouldBe CubeHash256(Sha256(Blake256(data)))
    }
  }


}
