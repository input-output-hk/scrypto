package scorex.crypto.authds.avltree

import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch._
import scorex.crypto.authds.legacy.avltree.AVLTree
import scorex.crypto.hash.Sha256

class AVLDeleteSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val KL = 26
  val VL = 8


  property("Batch delete") {
    var newProver = new BatchAVLProver(KL, VL)

    val aKey = Sha256("key 1").take(KL)
    val aValue = Sha256("value 1").take(VL)
    newProver.performOneOperation(Insert(aKey, aValue)).isSuccess shouldBe true
    newProver.generateProof

    newProver.performOneOperation(Update(aKey, aValue)).isSuccess shouldBe true
    newProver.generateProof

    newProver.performOneOperation(Remove(aKey)).isSuccess shouldBe true
    newProver.performOneOperation(Update(aKey, aValue)).isSuccess shouldBe false

  }

}
