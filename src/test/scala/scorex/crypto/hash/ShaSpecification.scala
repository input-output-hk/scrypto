package scorex.crypto.hash

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto._

class ShaSpecification extends PropSpec
with PropertyChecks
with GeneratorDrivenPropertyChecks
with Matchers {

  property("Sha256 doublehash(x) is hash(hash(x))") {
    forAll { data: Array[Byte] =>
      Sha256.doubleHash(data) should equal(Sha256.hash(Sha256.hash(data)))
    }
  }

  property("Sha256 no collisions") {
    forAll { (x: Array[Byte], y: Array[Byte]) =>
      whenever(!x.sameElements(y)) {
        Sha256.hash(x) should not equal Sha256.hash(y)
      }
    }
  }

  property("Sha256 hash comparing with externally computed value") {
    //checking sha256 result with http://www.xorbin.com/tools/sha256-hash-calculator
    bytes2hex(Sha256.hash("hello world".getBytes)) shouldBe "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    //test samples from a Qeditas unit test
    bytes2hex(Sha256.hash("")) shouldBe "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    bytes2hex(Sha256.hash("abc")) shouldBe "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    bytes2hex(Sha256.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) shouldBe "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  }

  property("Sha512 no collisions") {
    forAll { (x: Array[Byte], y: Array[Byte]) =>
      whenever(!x.sameElements(y)) {
        Sha512.hash(x) should not equal Sha512.hash(y)
      }
    }
  }

  property("Sha512 hash comparing with externally computed value") {
    bytes2hex(Sha512.hash("hello world".getBytes)) shouldBe "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
    bytes2hex(Sha512.hash("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f1".getBytes)) shouldBe "eedf5a9abf721bccbaf547ae5a26b29382043ed97c92a7b1fee75233115d681ffa537dfe644f66e80bd2537584f0829484eb8c8dc6b26d11811915025cf29f84"
  }

}
