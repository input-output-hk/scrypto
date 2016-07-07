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

import scala.util.Random

class SkipListSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators
with TestingCommons {
  val fileName = dirName + "SkipListSpecification.storage"
  new File(fileName).deleteOnExit()
  implicit val storage = new MvStoreBlobBlobStorage(Some(fileName))
  implicit val hf: CommutativeHash[Blake2b256.type] = CommutativeHash(Blake2b256)

  val sl = new SkipList()(storage, hf)

  property("SkipList special case") {
    val elements = genEl(100, Some(0))
    var oldE: Seq[SLElement] = Seq.empty
    elements.foreach { newE =>
      sl.insert(newE)
      oldE = newE +: oldE
      oldE.foreach { e =>
        assert(sl.elementProof(e).check(sl.rootHash))
      }
    }
  }



  property("SkipList mass update ") {
    val elements: Seq[SLElement] = genEl(100)
    sl.update(SkipListUpdate(toDelete = Seq(), toInsert = elements))
    val rh = sl.rootHash
    elements.foreach { e =>
      sl.contains(e) shouldBe true
      sl.elementProof(e) match {
        case p: SLExistenceProof => p.check(rh) shouldBe true
        case p: SLNonExistenceProof => assert(false)
      }
    }

    val toInsert: Seq[SLElement] = genEl(100)
    val toDelete = elements.take(10)
    sl.update(SkipListUpdate(toDelete = toDelete, toInsert = toInsert))
    toInsert.foreach { e =>
      sl.contains(e) shouldBe true
      sl.elementProof(e) match {
        case p: SLExistenceProof => p.check(sl.rootHash) shouldBe true
        case p: SLNonExistenceProof => assert(false)
      }
    }
    toDelete.foreach { e =>
      sl.contains(e) shouldBe false
    }

  }

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
        sl.delete(newSE)
        sl.contains(newSE) shouldBe false
        sl.topNode.down.get.right.get.el should not be MaxSLElement
      }
    }
  }

  property("SkipList hash of top element is computable") {
    sl.rootHash.length shouldBe hf.DigestSize
  }

  property("SkipList non-existent") {
    sl.update(SkipListUpdate(toDelete = Seq(), toInsert = genEl(100)))

    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)) {
        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
        val proof = sl.elementProof(newSE)
        proof match {
          case p: SLExistenceProof => p.check(sl.rootHash) shouldBe true
          case p: SLNonExistenceProof => assert(false)
        }

        sl.delete(newSE)
        sl.elementProof(newSE) match {
          case p: SLExistenceProof => assert(false)
          case p: SLNonExistenceProof =>
            p.check(sl.rootHash) shouldBe true
        }
      }
    }
  }

  property("SkipList proof is valid") {
    val oldElements = genEl(5)
    sl.update(SkipListUpdate(toDelete = Seq(), toInsert = oldElements))

    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)) {

        sl.insert(newSE) shouldBe true
        sl.contains(newSE) shouldBe true
        val proof = sl.elementProof(newSE)
        proof match {
          case p: SLExistenceProof => p.check(sl.rootHash) shouldBe true
          case p: SLNonExistenceProof => assert(false)
        }

        sl.delete(newSE)
        proof match {
          case p: SLExistenceProof => p.check(sl.rootHash) shouldBe false
          case p: SLNonExistenceProof => assert(false)
        }

        oldElements.foreach { e =>
          sl.elementProof(e).check(sl.rootHash) shouldBe true
        }
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
    sl2.update(SkipListUpdate(toDelete = Seq(), toInsert = genEl(100, Some(0))))
    Base58.encode(sl2.rootHash) shouldBe "Ewcvs6SqFUQyBRnjep3AV8Rhz6KE8jgxP2RnPe2dM5cJ"
  }

}
