package scorex.crypto.authds.sltree

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.binary.{SLTKey, SLTree}


class SLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {


  property("SLTree special case") {
    val slt = new SLTree()
    val digest = slt.rootHash()
    val key: SLTKey = Array.fill(32)(5: Byte)
    val value: SLTKey = Array.fill(32)(5: Byte)
    val (success, proof) = slt.insert(key, value)
    success shouldBe true
    slt.rootNode.right.isDefined shouldBe true
    proof.verifyInsert(digest)._1 shouldBe true
  }

  property("SLTree insert one") {
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty) {
        val slt = new SLTree()
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
      }
    }
  }

    property("SLTree insert") {
      val slt = new SLTree()
      forAll { (key: Array[Byte], value: Array[Byte]) =>
        whenever(key.nonEmpty && value.nonEmpty) {
          val digest = slt.rootHash()
          val (success, proof) = slt.insert(key, value)
          success shouldBe true
          proof.verifyInsert(digest)._1 shouldBe true
          proof.copy(key = proof.key ++ Array(0: Byte)).verifyInsert(digest)._1 shouldBe false
          proof.copy(value = proof.value ++ Array(0: Byte)).verifyInsert(digest)._1 shouldBe false
        }
      }
    }
/*
    property("SLTree lookup") {
      val slt = new SLTree()
      forAll { (key: Array[Byte], value: Array[Byte]) =>
        whenever(key.nonEmpty && value.nonEmpty) {
          slt.insert(key, value)._1 shouldBe true

          val digest = slt.rootHash()
          val (valueOpt, proof) = slt.lookup(key)
          valueOpt.get shouldBe value
        }
      }
    }

  */

}
