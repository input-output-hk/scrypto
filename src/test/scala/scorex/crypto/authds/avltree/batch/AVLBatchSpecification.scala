package scorex.crypto.authds.avltree.batch

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.legacy.AVLTree
import scorex.utils.Random

class AVLBatchSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val KL = 26
  val VL = 8
  val HL = 32

  property("zero-mods verification on empty tree") {
    val p = new BatchAVLProver()
    p.checkTree()
    val digest = p.rootHash
    val oldHeight = p.rootHeight
    val pf = p.generateProof.toArray
    p.checkTree(true)
    val v = new BatchAVLVerifier(digest, pf, 32, 8, oldHeight, Some(0), Some(0))
    v.digest match {
      case None =>
        require(false, "zero-mods verification failed to construct tree")
      case Some(d) =>
        require(d sameElements digest, "wrong digest for zero-mods")
        require(v.rootHeight == oldHeight, "wrong tree height for zero-mods")
    }
  }

  property("various verifier fails") {
    val p = new BatchAVLProver()

    p.checkTree()
    for (i <- 0 until 1000) {
      require(p.performOneModification(Insert(Random.randomBytes(), Random.randomBytes(8))).isSuccess, "failed to insert")
      p.checkTree()
    }
    p.generateProof

    var digest = p.rootHash
    var oldHeight = p.rootHeight
    for (i <- 0 until 50)
      require(p.performOneModification(Insert(Random.randomBytes(), Random.randomBytes(8))).isSuccess, "failed to insert")

    var pf = p.generateProof.toArray
    // see if the proof for 50 mods will be allowed when we permit only 2
    var v = new BatchAVLVerifier(digest, pf, 32, 8, oldHeight, Some(2), Some(0))
    require(v.digest.isEmpty, "Failed to reject too long a proof")

    // see if wrong digest will be allowed
    v = new BatchAVLVerifier(Random.randomBytes(), pf, 32, 8, oldHeight, Some(50), Some(0))
    require(v.digest.isEmpty, "Failed to reject wrong digest")

    for (i <- 0 until 10) {
      digest = p.rootHash
      oldHeight = p.rootHeight
      for (i <- 0 until 8)
        require(p.performOneModification(Insert(Random.randomBytes(), Random.randomBytes(8))).isSuccess, "failed to insert")

      v = new BatchAVLVerifier(digest, p.generateProof.toArray, 32, 8, oldHeight, Some(8), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      // Try 5 inserts that do not match -- with overwhelming probability one of them will go to a leaf
      // that is not in the conveyed tree, and verifier will complain
      for (i <- 0 until 5)
        v.performOneModification(Insert(Random.randomBytes(), Random.randomBytes(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed, because of a missing leaf")

      digest = p.rootHash
      oldHeight = p.rootHeight
      val key = Random.randomBytes()
      p.performOneModification(Insert(key, Random.randomBytes(8)))
      pf = p.generateProof.toArray
      p.checkTree()

      // Change the direction of the proof and make sure verifier fails
      pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
      v = new BatchAVLVerifier(digest, pf, 32, 8, oldHeight, Some(1), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      v.performOneModification(Insert(key, Random.randomBytes(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed, because of the wrong direction")

      // Change the key by a large amount -- verification should fail with overwhelming probability
      // because there are 1000 keys in the tree
      // First, change the proof back to be correct
      pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
      val oldKey = key(0)
      key(0) = (key(0) ^ (1 << 7)).toByte
      v = new BatchAVLVerifier(digest, pf, 32, 8, oldHeight, Some(1), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      v.performOneModification(Insert(key, Random.randomBytes(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed because of the wrong key")
      // put the key back the way it should be, because otherwise it's messed up in the prover tree
      key(0) = (key(0) ^ (1 << 7)).toByte

    }

  }

  property("succesful modifications") {
    // returns between 0 and max-1
    // TODO: switch to some library function -- this is quick and dirty, I just couldn't find the right
    // function to use
    def randomInt(max: Int) = {
      require(max < 2000000)
      require(max > 0)
      val j = Random.randomBytes(3)
      ((j(0) & 127) + (j(1) & 127) * 128 + (j(2) & 127) * 128 * 128) % max
    }

    val p = new BatchAVLProver()

    val numMods = 5000

    val deletedKeys = new scala.collection.mutable.ArrayBuffer[AVLKey]

    // TODO: Here we need a data structure that supports fast
    // random access by index; insert, delete, and modify (by index or by value -- we can work with either)
    // Something like a rank tree. I couldn't find anything standard in scala collections,
    // so I am using ArrayBuffer, which is terrible, because delete is slow.
    // ListBuffer would also be terrible here, because it doesn't have
    // fast lookup and remove by index
    // SetTree doesn't allow lookup by rank.
    val keysAndVals = new scala.collection.mutable.ArrayBuffer[(AVLKey, AVLValue)]

    var i = 0
    var numInserts = 0
    var numModifies = 0
    var numDeletes = 0
    var numNonDeletes = 0
    var numFailures = 0

    val t0 = System.nanoTime()
    while (i < numMods) {
      val digest = p.rootHash
      val oldHeight = p.rootHeight
      val n = randomInt(100)
      val j = i + n
      var numCurrentDeletes = 0
      val currentMods = new scala.collection.mutable.ArrayBuffer[Modification](n)
      while (i < j) {
        if (keysAndVals.isEmpty || randomInt(2) == 0) {
          // with prob .5 insert a new one, with prob .5 update or delete an existing one
          if (keysAndVals.nonEmpty && randomInt(10) == 0) {
            // with probability 1/10 cause a fail by inserting already existing
            val j = Random.randomBytes(3)
            val index = randomInt(keysAndVals.size)
            val key = keysAndVals(index)._1
            require(p.performOneModification(Insert(key, Random.randomBytes(8))).isFailure, "prover succeeded on inserting a value that's already in tree")
            p.checkTree()
            require(p.unauthenticatedLookup(key).get sameElements keysAndVals(index)._2, "value changed after duplicate insert") // check insert didn't do damage
            numFailures += 1
          }
          else {
            val key = Random.randomBytes()
            val newVal = Random.randomBytes(8)
            keysAndVals += ((key, newVal))
            val mod = Insert(key, newVal)
            currentMods += mod
            require(p.performOneModification(mod).isSuccess, "prover failed to insert")
            p.checkTree()
            require(p.unauthenticatedLookup(key).get sameElements newVal, "inserted key is missing") // check insert
            numInserts += 1
          }
        }
        else {
          // with probability .25 update, with .25 delete
          if (randomInt(2) == 0) {
            // update
            if (randomInt(10) == 0) {
              // with probability 1/10 cause a fail by modifying a nonexisting key
              val key = Random.randomBytes()
              require(p.performOneModification(Update(key, Random.randomBytes(8))).isFailure, "prover updated a nonexistent value")
              p.checkTree()
              require(p.unauthenticatedLookup(key).isEmpty, "a nonexistent value appeared after an update") // check update didn't do damage
              numFailures += 1
            }
            else {
              val index = randomInt(keysAndVals.size)
              val key = keysAndVals(index)._1
              val newVal = Random.randomBytes(8)
              val mod = Update(key, newVal)
              currentMods += mod
              require(p.performOneModification(mod).isSuccess, "prover failed to update value")
              keysAndVals(index) = (key, newVal)
              require(p.unauthenticatedLookup(key).get sameElements newVal, "wrong value after update") // check update
              numModifies += 1
            }
          } else {
            // delete
            if (randomInt(10) == 0) {
              // with probability 1/10 remove a nonexisting one but without failure -- shouldn't change the tree
              val key = Random.randomBytes()
              val mod = RemoveIfExists(key)
              val d = p.rootHash
              currentMods += mod
              require(p.performOneModification(mod).isSuccess, "prover failed when it should have done nothing")
              require(d sameElements p.rootHash, "Tree changed when it shouldn't have")
              p.checkTree()
              numNonDeletes += 1
            }
            else {
              // remove an existing key
              val index = randomInt(keysAndVals.size)
              val key = keysAndVals(index)._1
              val mod = Remove(key)
              val oldVal = keysAndVals(index)._2
              currentMods += mod
              val m = Modification.convert(mod)
              require(p.performOneModification(m._1, m._2).isSuccess, "failed ot delete")
              keysAndVals -= ((key, oldVal))
              deletedKeys += key
              require(p.unauthenticatedLookup(key).isEmpty, "deleted key still in tree") // check delete
              numDeletes += 1
              numCurrentDeletes += 1
            }
          }
        }
        i += 1
      }

      val pf = p.generateProof.toArray
      p.checkTree(true)

      val v = new BatchAVLVerifier(digest, pf, 32, 8, oldHeight, Some(n), Some(numCurrentDeletes))
      v.digest match {
        case None =>
          require(false, "Verification failed to construct the tree")
        case Some(d) =>
          require(d sameElements digest, "Built tree with wrong digest") // Tree built successfully
          require(v.rootHeight == oldHeight, "Built tree of wrong height")
      }

      Modification.convert(currentMods) foreach (m => v.performOneModification(m._1, m._2))
      v.digest match {
        case None =>
          require(false, "Verification failed")
        case Some(d) =>
          require(d sameElements p.rootHash, "Tree has wrong digest after verification")
          require(v.rootHeight == p.rootHeight, "Tree has wrong height after verification")
      }
    }

    // Check that all the inserts, deletes, and updates we did actually stayed
    deletedKeys foreach (k => require(p.unauthenticatedLookup(k).isEmpty, "Key that was deleted is still in the tree"))
    keysAndVals foreach (pair => require(p.unauthenticatedLookup(pair._1).get sameElements pair._2, "Key has wrong value"))
  }


  //TODO rollback and recover
  property("Persistence AVL batch prover") {
    val storage = new VersionedAVLStorageMock
    val prover = new PersistentBatchAVLProver(new BatchAVLProver(KL, VL), storage)
    var digest = prover.rootHash

    forAll(kvGen) { case (aKey, aValue) =>
      val m = Insert(aKey, aValue)
      prover.performOneModification(m)
      val pf = prover.generateProof
      val verifier = new BatchAVLVerifier(digest, pf, KL, VL)
      verifier.performOneModification(m)
      prover.rootHash should not equal digest
      prover.rootHash shouldEqual verifier.digest.get

      //      prover.rollback(digest).isSuccess shouldBe true
      //      prover.rootHash shouldEqual digest
      //      prover.performOneModification(m)
      //      prover.generateProof
      digest = prover.rootHash
    }

    //    val prover2 = new PersistentBatchAVLProver(new BatchAVLProver(KL, VL), storage)
    //    prover2.rootHash shouldEqual prover.rootHash
  }

  property("Updates with and without batching should lead to the same tree") {
    val tree = new AVLTree(KL)
    var digest = tree.rootHash()
    val oldProver = new oldProver(tree)
    val newProver = new BatchAVLProver(KL, VL)
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
    val prover = new BatchAVLProver(KL, VL)
    var digest = prover.rootHash

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Modification.convert(Seq(Insert(aKey, aValue)))

      currentMods foreach (m => prover.performOneModification(m._1, m._2))
      val pf = prover.generateProof.toArray

      val verifier = new BatchAVLVerifier(digest, pf, KL, VL)
      currentMods foreach (m => verifier.performOneModification(m._1, m._2))
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
