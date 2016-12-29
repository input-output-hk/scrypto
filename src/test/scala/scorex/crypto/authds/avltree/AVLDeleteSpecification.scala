package scorex.crypto.authds.avltree

import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch._
import scorex.crypto.authds.avltree.legacy.AVLTree
import scorex.crypto.hash.Sha256

class AVLDeleteSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val KL = 26
  val VL = 8


  property("Batch delete") {
    var newProver = new BatchAVLProver(KL, VL)

    val aKey = Sha256("key 1").take(KL)
    val aValue = Sha256("value 1").take(VL)
    newProver.performOneModification(Insert(aKey, aValue)).isSuccess shouldBe true
    newProver.generateProof

    newProver.performOneModification(Update(aKey, aValue)).isSuccess shouldBe true
    newProver.generateProof

    newProver.performOneModification(Remove(aKey)).isSuccess shouldBe true
    newProver.performOneModification(Update(aKey, aValue)).isSuccess shouldBe false

  }

  ignore("delete") {
    val tree = new AVLTree(KL)
    val aKey = Sha256("key 1").take(KL)
    val aValue = Sha256("value 1").take(VL)

    //insert key
    tree.modify(aKey, insertOnly(aValue)).isSuccess shouldBe true
    val digest1 = tree.rootHash()
    //try to insert one more time
    tree.modify(aKey, insertOnly(aValue)).isSuccess shouldBe false

    //remove key
    tree.remove(aKey).isSuccess shouldBe true
    //should be able to insert key one more time
    tree.modify(aKey, insertOnly(aValue)).isSuccess shouldBe true
    //delete and insert should result to the same tree
    tree.rootHash() shouldEqual digest1
  }

}
