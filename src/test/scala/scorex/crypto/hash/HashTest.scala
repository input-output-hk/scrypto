package scorex.crypto.hash

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.encode.Base16

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._
import scala.concurrent.{Await, Future}

trait HashTest extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers {
  val emptyBytes: Array[Byte] = Array.empty

  def hashCheckString(hash: CryptographicHash[_ <: Digest], external: Map[String, String]): Unit =
    hashCheck(hash, external.map(x => x._1.getBytes("UTF-8") -> x._2))

  def hashCheck[D <: Digest](hash: CryptographicHash[D], external: Map[Array[Byte], String]): Unit = {

    property(s"${hash.getClass.getSimpleName} size of hash should be DigestSize") {
      forAll { data: Array[Byte] =>
        hash.hash(data).length shouldBe hash.DigestSize
      }
    }

    property(s"${hash.getClass.getSimpleName} no collisions") {
      forAll { (x: Array[Byte], y: Array[Byte]) =>
        whenever(!x.sameElements(y)) {
          hash.hash(x) should not equal hash.hash(y)
        }
      }
    }

    property(s"${hash.getClass.getSimpleName} comparing with externally computed value") {
      external.foreach { m =>
        Base16.encode(hash.hash(m._1)) shouldBe m._2.toLowerCase
      }
    }

    property(s"${hash.getClass.getSimpleName} is thread safe") {
      val singleThreadHashes = (0 until 100).map(i => hash.hash(i.toString))
      val multiThreadHashes = Future.sequence((0 until 100).map(i => Future(hash.hash(i.toString))))
      singleThreadHashes.map(Base16.encode(_)) shouldBe Await.result(multiThreadHashes, 1.minute).map(Base16.encode(_))
    }

    property(s"${hash.getClass.getSimpleName} apply method") {
      forAll { (string: String, bytes: Array[Byte]) =>
        hash(string) shouldEqual hash.hash(string)
        hash(string) shouldEqual hash(string.getBytes("UTF-8"))
        hash(bytes) shouldEqual hash.hash(bytes)
      }
    }


    property(s"${hash.getClass.getSimpleName} should return correct Tag") {
      forAll { (string: String, bytes: Array[Byte]) =>
        val digest = hash(string)
        digest.isInstanceOf[D] shouldBe true
        if (digest.isInstanceOf[Digest32]) {
          hash.DigestSize shouldBe 32
        } else if (digest.isInstanceOf[Digest64]) {
          hash.DigestSize shouldBe 64
        }
      }
    }
  }
}
