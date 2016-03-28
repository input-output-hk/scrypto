package scorex.crypto.ads.merkle

import java.io.{FileOutputStream, File}
import org.scalacheck.Arbitrary
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.utils.Random.randomBytes

import scala.util.Random

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

  def generateFile(blocks: Int, subdir: String = "1"): (String, File, String) = {
    val treeDirName = "/tmp/scorex-test/test/" + subdir + "/"
    val treeDir = new File(treeDirName)
    val tempFile = treeDirName + "/data.file"

    val data = new Array[Byte](1024 * blocks)
    Random.nextBytes(data)
    treeDir.mkdirs()
    for (file <- treeDir.listFiles) file.delete

    val fos = new FileOutputStream(tempFile)
    fos.write(data)
    fos.close()
    (treeDirName, treeDir, tempFile)
  }
}