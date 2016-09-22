package scorex.crypto.authds.sltree

import com.google.common.primitives.Longs
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.wtree._


class SLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {


  property("SLTree TwoPartyProof interface") {

  }


  property("SLTree stream") {
    val slt = new SLTree()
    slt.insert(Array(0: Byte), _ => Longs.toByteArray(Long.MaxValue))
    var digest: Array[Byte] = slt.rootHash()
    def updateFunction(amount: Long): Option[SLTValue] => SLTValue = (old: Option[SLTValue]) =>
      Longs.toByteArray(old.map(v => Longs.fromByteArray(v) + amount).getOrElse(amount))

    forAll { (sender: Array[Byte], recipient: Array[Byte], amount: Long) =>
      whenever(sender.nonEmpty && recipient.nonEmpty && amount >= 0) {
        //proover
        val senderProof: SLTModifyingProof = slt.modify(sender, updateFunction(-amount))
        val recipientProof: SLTModifyingProof = slt.modify(recipient, updateFunction(amount))

        //verifier
        senderProof.key shouldBe sender
        digest = senderProof.verify(digest, updateFunction(-amount)).get

        recipientProof.key shouldBe recipient
        digest = recipientProof.verify(digest, updateFunction(amount)).get
      }
    }
  }


  property("SLTree insert one") {
    forAll {
      (key: Array[Byte], value: Array[Byte]) =>
        whenever(key.nonEmpty && value.nonEmpty) {
          val slt = new SLTree()
          val digest = slt.rootHash()
          val (success, proof) = slt.insert(key, _ => value)
          success shouldBe true
          val newDigest = proof.verify(digest, rewrite(value)).get
          newDigest shouldEqual slt.rootHash()
        }
    }
  }

  property("SLTree insert") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, _ => value)
        success shouldBe true
        val newDigest = proof.verify(digest, rewrite(value)).get
        newDigest shouldEqual slt.rootHash()
      }
    }
  }

  property("SLTree lookup one") {
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty) {
        val slt = new SLTree()
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, _ => value)
        success shouldBe true

        val digest2 = slt.rootHash()
        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt.get shouldBe value
        lookupProof.verify(digest2).isDefined shouldBe true
      }
    }
  }

  property("SLTree lookup") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, _ => value)
        success shouldBe true

        val digest2 = slt.rootHash()
        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt.get shouldBe value
        lookupProof.verify(digest2).isDefined shouldBe true
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
        lookupProof.verify(digest) shouldBe None
      }
    }
  }

  property("SLTree update one ") {
    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty) {
        val slt = new SLTree()
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, _ => value)
        success shouldBe true
        proof.verify(digest, rewrite(value)).isDefined shouldBe true

        val digest2 = slt.rootHash()
        val (successUpdate, updateProof) = slt.update(key, _ => newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        val newDigest = updateProof.verify(digest2, rewrite(newVal)).get
        newDigest shouldEqual slt.rootHash()
      }
    }
  }

  property("SLTree update") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, _ => value)
        success shouldBe true
        proof.verify(digest, rewrite(value)).isDefined shouldBe true

        val digest2 = slt.rootHash()
        val (successUpdate, updateProof) = slt.update(key, valueConcat(newVal))
        successUpdate shouldBe true
        slt.lookup(key)._1.get.take(newVal.length) shouldEqual newVal
        val newDigest = updateProof.verify(digest2, valueConcat(newVal)).get
        newDigest shouldEqual slt.rootHash()
      }
    }
  }

  def valueConcat(v: SLTValue) = (old: Option[SLTValue]) => old.map(o => v ++ o).getOrElse(v)

  def rewrite(value: SLTValue): UpdateFunction = { oldOpt: Option[SLTValue] => value }

}
