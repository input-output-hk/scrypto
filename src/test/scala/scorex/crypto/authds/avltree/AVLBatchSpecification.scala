package scorex.crypto.authds.avltree.batch

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch

class AVLBatchSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val KL = 26
  val VL = 8

  property("Updates with and without batching should lead to the same tree") {
    val tree = new scorex.crypto.authds.avltree.AVLTree(26)
    var digest = tree.rootHash()
    val oldProver = new oldProver(tree)
    val newProver = new BatchAVLProver(None, 26, 8)
    oldProver.rootHash shouldBe newProver.rootHash

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Seq(Insert(aKey, aValue))
      oldProver.applyBatchSimple(currentMods) match {
        case bss: BatchSuccessSimple =>
          new oldVerifier(digest).verifyBatchSimple(currentMods, bss) shouldBe true
        case bf: BatchFailure => throw bf.error
      }

      Modification.convert(currentMods) foreach (m => newProver.performOneModification(m._1, m._2))
      val pf = newProver.generateProof.toArray

      digest = oldProver.rootHash
      oldProver.rootHash shouldBe newProver.rootHash
    }
    newProver.checkTree(true)
  }

  property("Verifier should calculate the same digest") {
    val prover = new BatchAVLProver(None, KL, VL)
    var digest = prover.rootHash

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Modification.convert(Seq(Insert(aKey, aValue)))

      currentMods foreach (m => prover.performOneModification(m._1, m._2))
      val pf = prover.generateProof.toArray

      val verifier = new BatchAVLVerifier(digest, pf, KL, VL)
      currentMods foreach (m => verifier.verifyOneModification(m._1, m._2))
      digest = verifier.digest.get

      prover.rootHash shouldEqual digest
    }
    prover.checkTree(true)
  }


  def kvGen: Gen[(Array[Byte], Array[Byte])] = for {
    key <- Gen.listOfN(KL, Arbitrary.arbitrary[Byte]).map(_.toArray) suchThat
      (k => !(k sameElements Array.fill(KL)(-1: Byte)) && !(k sameElements Array.fill(KL)(0: Byte)) && k.length == KL)
    value <- Gen.listOfN(VL, Arbitrary.arbitrary[Byte]).map(_.toArray)
  } yield (key, value)



}
