package scorex.crypto.authds.sltree

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.binary.{SLTValue, SLTKey, SLTree}


class SLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {

/*
  property("SLTree proof changed key") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte], newKey: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && newKey.nonEmpty && !(key sameElements newKey) && value.nonEmpty
        && newVal.nonEmpty && slt.lookup(key)._1.isEmpty) {

        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true
        proof.copy(key = newKey).isValid(digest) shouldBe false


      }
    }
  }
*/


  property("SLTree proof double check") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt.get shouldBe value
        lookupProof.isValid(digest2) shouldBe true
        lookupProof.isValid(digest2) shouldBe true

        val (successUpdate, updateProof) = slt.update(key, newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        updateProof.isValid(digest2) shouldBe true
        updateProof.isValid(digest2) shouldBe true
      }
    }
  }

  property("SLTree insert one") {
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty) {
        val slt = new SLTree()
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        val (verifies, insertSuccess, newDigest) = proof.verifyInsert(digest).get
        verifies shouldBe true
        insertSuccess shouldBe true
        newDigest shouldEqual slt.rootHash()
      }
    }
  }

  property("SLTree insert") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        val (verifies, insertSuccess, newDigest) = proof.verifyInsert(digest).get
        verifies shouldBe true
        insertSuccess shouldBe true
        newDigest shouldEqual slt.rootHash()
      }
    }
  }

  property("SLTree lookup one") {
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty) {
        val slt = new SLTree()
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt.get shouldBe value
        lookupProof.isValid(digest2) shouldBe true
      }
    }
  }

  property("SLTree lookup") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt.get shouldBe value
        lookupProof.isValid(digest2) shouldBe true
      }
    }
  }

  property("SLTree non-existent lookup") {
    val slt = new SLTree()
    forAll { (key: Array[Byte]) =>
      whenever(key.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()

        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt shouldBe None
        lookupProof.isValid(digest) shouldBe true
      }
    }
  }

  property("SLTree update one ") {
    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty) {
        val slt = new SLTree()
        slt.rootNode.right.isDefined shouldBe false
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (successUpdate, updateProof) = slt.update(key, newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        updateProof.isValid(digest2) shouldBe true
      }
    }
  }

  property("SLTree update") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (successUpdate, updateProof) = slt.update(key, newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        updateProof.isValid(digest2) shouldBe true

      }
    }
  }

}
