package scorex.crypto.authds.sltree

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.binary.{SLTKey, SLTree}


class SLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {


  property("SLTree insert one") {
    val slt = new SLTree()
    val digest = slt.rootHash()
    val key: SLTKey = Array.fill(32)(0: Byte)
    val value: SLTKey = Array.fill(32)(1: Byte)
    val (success, proof) = slt.insert(key, value)
    success shouldBe true
    proof.verifyInsert(digest)._1 shouldBe true
  }

  /*
    property("SLTree insert") {
      forAll { (key: Array[Byte], value: Array[Byte]) =>


      }
    }
  */

}
