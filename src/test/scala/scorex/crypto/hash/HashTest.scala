package scorex.crypto.hash

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto._

trait HashTest extends PropSpec
with PropertyChecks
with GeneratorDrivenPropertyChecks
with Matchers {
  val emptyBytes: Array[Byte] = Array.empty

  def hashCheckString(hash: CryptographicHash, external: Map[String, String]): Unit =
    hashCheck(hash, external.map(x => (x._1.getBytes -> x._2)))

  def hashCheck(hash: CryptographicHash, external: Map[Array[Byte], String]): Unit = {
    property(s"${hash.getClass.getSimpleName} doublehash(x) is hash(hash(x))") {
      forAll { data: Array[Byte] =>
        hash.doubleHash(data) should equal(hash.hash(hash.hash(data)))
      }
    }

    property(s"${hash.getClass.getSimpleName} size of hash should be DigestSize") {
      forAll { data: Array[Byte] =>
        hash.hash(data).length shouldBe hash.DigestSize
      }
    }

    property(s"${hash.getClass.getSimpleName} no collisions") {
      forAll { (x: Array[Byte], y: Array[Byte]) =>
        whenever(!x.sameElements(y)) {
          hash.hash(x) should not equal Sha256.hash(y)
        }
      }
    }

    property(s"${hash.getClass.getSimpleName} comparing with externally computed value") {
      external.foreach { m =>
        bytes2hex(hash.hash(m._1)) shouldBe m._2.toLowerCase
      }
    }
  }

}
