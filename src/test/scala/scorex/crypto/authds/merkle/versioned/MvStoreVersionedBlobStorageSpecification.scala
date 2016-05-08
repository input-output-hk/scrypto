package scorex.crypto.authds.merkle.versioned

import org.scalacheck.Gen
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreVersionedBlobStorage

class MvStoreVersionedBlobStorageSpecification
  extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers {

  property("rollback to version 1") {
    val bs = new MvStoreVersionedBlobStorage(None)

    bs.batchUpdate(Seq(0L -> Some(Array.fill(5)(0: Byte)), 1L -> Some(Array.fill(7)(1: Byte))))

    println(bs.allVersions())
    bs.size shouldBe 2

    forAll(Gen.listOf(Gen.alphaStr), minSuccessful(50), maxDiscarded(1)) { strings: List[String] =>
      val blobs = strings.map(_.getBytes)
      val upd = blobs.zipWithIndex.map { case (blob, i) =>
        (bs.size + i) -> Some(blob)
      }
      bs.batchUpdate(upd)
    }


    (bs.size > 2) shouldBe true

    val rollbackStatus = bs.rollbackTo(1)
    rollbackStatus.isSuccess shouldBe true

    bs.size shouldBe 2
  }

}
