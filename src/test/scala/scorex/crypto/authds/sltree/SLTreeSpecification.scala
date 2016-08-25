package scorex.crypto.authds.sltree

import com.google.common.primitives.Longs
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons

import scala.util.Random


class SLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {

  property("SLTree tx update") {
    val slt = new SLTree()
    slt.insert(Array(0: Byte), _ => Longs.toByteArray(Long.MaxValue))
    var digest: Array[Byte] = slt.rootHash()
    def updateFunction(amount: Long): Option[SLTValue] => SLTValue = (old: Option[SLTValue]) =>
      Longs.toByteArray(old.map(v => Longs.fromByteArray(v) + amount).getOrElse(amount))

    //    def modN(n: Int)(x: Int) = ((x % n) == 0)
    forAll { (sender: Array[Byte], recipient: Array[Byte], amount: Long) =>
      whenever(sender.nonEmpty && recipient.nonEmpty && amount >= 0) {
        //proover
        //change sender balance
        val (_, senderProof: SLTProof) = slt.lookup(sender)._1 match {
          case Some(_) =>
            slt.update(sender, updateFunction(-amount))
          case None =>
            slt.insert(sender, updateFunction(-amount))
        }
        //change recipient balance
        val (_, recipientProof: SLTProof) = slt.lookup(recipient)._1 match {
          case Some(_) =>
            slt.update(recipient, updateFunction(amount))
          case None =>
            slt.insert(recipient, updateFunction(amount))
        }

        //verifier
        //check sender proof
        senderProof match {
          case proof: SLTInsertProof =>
            proof.key shouldBe sender
            digest = proof.verify(digest, updateFunction(-amount)).get

          case proof: SLTUpdateProof =>
            proof.key shouldBe sender
            digest = proof.verify(digest, updateFunction(-amount)).get
          case _ => throw new Error()
        }
        //check recipient proof
        recipientProof match {
          case proof: SLTInsertProof =>
            proof.key shouldBe recipient
            digest = proof.verify(digest, updateFunction(amount)).get

          case proof: SLTUpdateProof =>
            proof.key shouldBe recipient
            digest = proof.verify(digest, updateFunction(amount)).get

          case _ => throw new Error()
        }

      }
    }
  }



  property("SLTree stream") {
    val slt = new SLTree()
    var digest: Array[Byte] = slt.rootHash()
    var keys: Seq[Array[Byte]] = Seq()

    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty && slt.lookup(key)._1.isEmpty) {
        keys = key +: keys
        val (success, proof) = slt.insert(key, _ => value)
        success shouldBe true
        digest = proof.verify(digest, _ => value).get

        val uKey = keys(Random.nextInt(keys.length))
        val (successUpdate, updateProof) = slt.update(uKey, _ => newVal)
        successUpdate shouldBe true
        slt.lookup(uKey)._1.get shouldBe newVal
        digest = updateProof.verify(digest, _ => newVal).get
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
          val newDigest = proof.verify(digest, _ => value).get
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
        val newDigest = proof.verify(digest, _ => value).get
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
        proof.verify(digest, _ => value).isDefined shouldBe true

        val digest2 = slt.rootHash()
        val (successUpdate, updateProof) = slt.update(key, _ => newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        val newDigest = updateProof.verify(digest2, _ => newVal).get
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
        proof.verify(digest, _ => value).isDefined shouldBe true

        val digest2 = slt.rootHash()
        val (successUpdate, updateProof) = slt.update(key, _ => newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        val newDigest = updateProof.verify(digest2, _ => newVal).get
        newDigest shouldEqual slt.rootHash()
      }
    }
  }


}
