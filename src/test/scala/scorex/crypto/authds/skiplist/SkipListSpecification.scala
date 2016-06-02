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

  def getNewEl = NormalSLElement(randomBytes(), randomBytes())


  property("SkipList rightNode hash") {
    sl.topNode.right.get.hash.length shouldBe hf.DigestSize
  }

  property("SkipList hash") {
    println(sl)

    (0 until 2) foreach { i =>
      val newSE = NormalSLElement(Ints.toByteArray(i), Ints.toByteArray(i))
      sl.insert(newSE) shouldBe true
      println("====")
      println(sl)
      val proof = sl.elementProof(newSE).get
      proof.check(sl.rootHash) shouldBe true
    }

    val newSE2 = NormalSLElement(Array.fill(32)(2: Byte), Array.fill(32)(-2: Byte))
    sl.insert(newSE2) shouldBe true
    println("====")
    println(sl)
    val proof2 = sl.elementProof(newSE2).get
    proof2.check(sl.rootHash) shouldBe true


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


}
