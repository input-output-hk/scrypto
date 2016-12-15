package scorex.crypto.authds.avltree

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import scorex.crypto.authds.avltree.batch._
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.TwoPartyTests

class AVLBatchSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val KL = 26
  val VL = 8
  val HL = 32

  //TODO rollback and recover
  property("Persistence AVL batch prover") {
    val storage = new VersionedAVLStorageMock
    val prover = new PersistentBatchAVLProver(new BatchAVLProver(None, KL, VL), storage)
    var digest = prover.rootHash

    forAll(kvGen) { case (aKey, aValue) =>
      val m = Insert(aKey, aValue)
      prover.performOneModification(m)
      val pf = prover.generateProof
      val verifier = new BatchAVLVerifier(digest, pf, KL, VL)
      verifier.verifyOneModification(m)
      prover.rootHash should not equal digest
      prover.rootHash shouldEqual verifier.digest.get

//      prover.rollback(digest).isSuccess shouldBe true
//      prover.rootHash shouldEqual digest
//      prover.performOneModification(m)
//      prover.generateProof
      digest = prover.rootHash
    }

    //    val prover2 = new PersistentBatchAVLProver(new BatchAVLProver(None, KL, VL), storage)
    //    prover2.rootHash shouldEqual prover.rootHash
  }

  property("Updates with and without batching should lead to the same tree") {
    val tree = new scorex.crypto.authds.avltree.AVLTree(KL)
    var digest = tree.rootHash()
    val oldProver = new oldProver(tree)
    val newProver = new BatchAVLProver(None, KL, VL)
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
