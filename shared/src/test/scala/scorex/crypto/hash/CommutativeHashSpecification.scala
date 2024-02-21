package scorex.crypto.hash

class CommutativeHashSpecification extends HashTest {

  val hash = new CommutativeHash(Sha256)

  property(s"CommutativeHash(Sha256) is CryptographicHash") {
    forAll { (data: Array[Byte]) =>
      hash.hash(data).length shouldBe hash.DigestSize
    }

    forAll { (x: Array[Byte], y: Array[Byte]) =>
      whenever(!x.sameElements(y)) {
        hash.hash(x) should not equal hash.hash(y)
      }
    }
  }

  property(s"CommutativeHash(Sha256) no collisions") {
    forAll { (x: Array[Byte], y: Array[Byte], z: Array[Byte]) =>
      whenever(!x.sameElements(y) && !x.sameElements(z) && !z.sameElements(y)) {
        hash.hash(x, y) should not equal hash.hash(x, z)
        hash.hash(x, y) should not equal hash.hash(z, y)
      }
    }
  }

  property(s"CommutativeHash(Sha256) is commutative") {
    forAll { (x: Array[Byte], y: Array[Byte]) =>
        hash.hash(x, y) shouldEqual hash.hash(y, x)
    }
  }
}
