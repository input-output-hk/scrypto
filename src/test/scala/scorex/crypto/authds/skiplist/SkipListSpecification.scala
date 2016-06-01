package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class SkipListSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {
  implicit val storage = new MvStoreBlobBlobStorage(None)

  val sl = new SkipList
  implicit val hf: CommutativeHash[Blake2b256.type] = CommutativeHash(Blake2b256)

  property("SkipList should contain inserted element") {
    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)) {
        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
      }
    }
  }
//
//  property("SkipList should not contain deleted element") {
//    forAll(slelementGenerator) { newSE: SLElement =>
//      whenever(!sl.contains(newSE)) {
//        sl.insert(newSE) shouldBe true
//        sl.contains(newSE) shouldBe true
//        sl.delete(newSE) shouldBe true
//        sl.contains(newSE) shouldBe false
//      }
//    }
//  }
//
//  property("SkipList hash of top element is computable") {
//    sl.topNode.hash.length shouldBe hf.DigestSize
//  }
//
//  property("SkipList proof is valid") {
//    val sl = new SkipList
//    forAll(slelementGenerator) { newSE: SLElement =>
//      whenever(!sl.contains(newSE)) {
//        sl.insert(newSE) shouldBe true
//        sl.contains(newSE) shouldBe true
//        val proof = sl.elementProof(newSE).get
//        proof.check(sl.topNode.hash) shouldBe true
//
//        sl.delete(newSE)
//        proof.check(sl.topNode.hash) shouldBe false
//      }
//    }
//  }
//

}
