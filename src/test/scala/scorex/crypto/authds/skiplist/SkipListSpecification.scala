package scorex.crypto.authds.skiplist

import java.io.File

import com.google.common.primitives.Ints
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, CommutativeHash}
import scorex.utils.Random.randomBytes

class SkipListSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators
with TestingCommons {
  val fileName = dirName + "SkipListSpecification.storage"
  new File(fileName).deleteOnExit()
  implicit val storage = new MvStoreBlobBlobStorage(Some(fileName))
  implicit val hf: CommutativeHash[Blake2b256.type] = CommutativeHash(Blake2b256)

  val sl = new SkipList()(storage, hf)

  property("SkipList rightNode hash") {
    sl.topNode.right.get.hash.length shouldBe hf.DigestSize
  }

  property("SkipList should contain inserted element") {
    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)) {
        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
      }
    }
  }

  property("SkipList should not contain deleted element") {
    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)) {
        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
        sl.delete(newSE) shouldBe true
        sl.contains(newSE) shouldBe false
        sl.topNode.down.get.right.get.el should not be MaxSLElement
      }
    }
  }

  property("SkipList hash of top element is computable") {
    sl.rootHash.length shouldBe hf.DigestSize
  }

  property("SkipList proof is valid") {
    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)) {
        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
        val proof = sl.elementProof(newSE).get
        proof.check(sl.rootHash) shouldBe true

        sl.delete(newSE)
        proof.check(sl.rootHash) shouldBe false
      }
    }
  }

  property("SkipList reopening") {
    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)) {
        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
        val rh = sl.rootHash
        val sl2 = new SkipList()(storage, hf)
        sl2.contains(newSE) shouldBe true
        (sl2.rootHash sameElements rh) shouldBe true

      }
    }
  }

  property("SkipList should be deterministic") {
    val sl2 = new SkipList()(new MvStoreBlobBlobStorage(None), hf)
    (1 to 64).foreach{ i =>
      sl2.insert(NormalSLElement(Ints.toByteArray(i), Ints.toByteArray(i)))
    }
    Base58.encode(sl2.rootHash) shouldBe "AgWUNSemho4LgUECCftLftvqybhaCETrMtXhem2P3vvu"
  }


}
