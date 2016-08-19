package scorex.crypto.authds.sltree

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.binary.{SLTKey, SLTree}
import scorex.utils.ByteArray


class SLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {


  property("SLTree special case") {
    val slt = new SLTree()
    val digest = slt.rootHash()
    val key: SLTKey = Array.fill(32)(5: Byte)
    val value: SLTKey = Array.fill(32)(5: Byte)
    val (success, proof) = slt.insert(key, value)
    success shouldBe true
    proof.verifyInsert(digest)._1 shouldBe true

    val digest2 = slt.rootHash()
    val key2: SLTKey = Array.fill(32)(4: Byte)
    require(ByteArray.compare(key2, key) < 0)

    val value2: SLTKey = Array.fill(32)(4: Byte)
    val (success2, proof2) = slt.insert(key, value)
    success2 shouldBe true
    proof2.verifyInsert(digest2)._1 shouldBe true

  }

  property("SLTree insert one") {
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      val slt = new SLTree()
      val digest = slt.rootHash()
      val (success, proof) = slt.insert(key, value)
      success shouldBe true
      proof.verifyInsert(digest)._1 shouldBe true
    }
  }

  property("SLTree insert") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      val digest = slt.rootHash()
      val (success, proof) = slt.insert(key, value)
      success shouldBe true
      proof.verifyInsert(digest)._1 shouldBe true
      proof.copy(key = proof.key ++ Array(0: Byte)).verifyInsert(digest)._1 shouldBe false
      proof.copy(value = proof.value ++ Array(0: Byte)).verifyInsert(digest)._1 shouldBe false
    }
  }

}
