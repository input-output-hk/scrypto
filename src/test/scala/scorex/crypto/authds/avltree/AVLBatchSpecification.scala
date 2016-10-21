package scorex.crypto.authds.avltree

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch.{oldProver, _}
import scorex.crypto.encode.Base58

class AVLBatchSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests with ADSUser {

  val KL = 26
  val VL = 8

  property("Updates with and without batching should lead to the same tree") {
    val tree = new AVLTree(26)
    var digest = tree.rootHash()
    val oldProver = new oldProver(tree)
    val newProver = new BatchAVLProver(None, 32, 26, 8)
    oldProver.rootHash shouldBe newProver.rootHash

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Seq(Insert(aKey, aValue))
      oldProver.applyBatchSimple(currentMods) match {
        case bss: BatchSuccessSimple =>
          new oldVerifier(digest).verifyBatchSimple(currentMods, bss) shouldBe true
        case bf: BatchFailure => throw bf.error
      }

      convert(currentMods) foreach (m => newProver.performOneModification(m._1, m._2))
      val pf = newProver.generateProof.toArray

      val newVerifier = new BatchAVLVerifier(digest, pf)
      digest = oldProver.rootHash
      //TODO ???
//      newVerifier.digest.get shouldEqual digest
      oldProver.rootHash shouldBe newProver.rootHash
    }
  }

  def kvGen: Gen[(Array[Byte], Array[Byte])] = for {
    key <- Gen.listOfN(KL, Arbitrary.arbitrary[Byte]).map(_.toArray) suchThat
      (k => !(k sameElements Array.fill(KL)(-1: Byte)) && !(k sameElements Array.fill(KL)(0: Byte)) && k.length == KL)
    value <- Gen.listOfN(VL, Arbitrary.arbitrary[Byte]).map(_.toArray)
  } yield (key, value)


}
