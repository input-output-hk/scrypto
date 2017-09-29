package scorex.crypto.authds.avltree.batch

import com.google.common.primitives.Longs
import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.{ADDigest, ADKey, ADValue, TwoPartyTests}
import scorex.crypto.authds.legacy.avltree.AVLTree
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256Unsafe, _}
import scorex.utils.{ByteArray, Random}

import scala.util.Random.{nextInt => randomInt}
import scala.util.{Failure, Try}

class AVLBatchSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val KL = 26
  val VL = 8
  val HL = 32
  type T = Digest32
  type HF = Blake2b256Unsafe
  
  def randomKey(size: Int = 32): ADKey = ADKey @@ Random.randomBytes(size)
  def randomValue(size: Int = 32): ADValue = ADValue @@ Random.randomBytes(size)

  property("unauthenticatedLookup") {
    val p = new BatchAVLProver[Digest32, Blake2b256Unsafe](keyLength = 8, valueLengthOpt = None)

    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(1.toLong), ADValue @@ Array.fill(4)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(2.toLong), ADValue @@ Array.fill(5)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(3.toLong), ADValue @@ Array.fill(6)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(4.toLong), ADValue @@ Array.fill(7)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(5.toLong), ADValue @@ Array.fill(8)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(6.toLong), ADValue @@ Array.fill(9)(0: Byte)))


    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(0.toLong)) shouldBe None
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(1.toLong)).get.length shouldBe 4
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(2.toLong)).get.length shouldBe 5
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(3.toLong)).get.length shouldBe 6
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(4.toLong)).get.length shouldBe 7
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(5.toLong)).get.length shouldBe 8
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(6.toLong)).get.length shouldBe 9
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(7.toLong)) shouldBe None
  }

  property("BatchAVLVerifier: extractNodes and extractFirstNode") {
    val TreeSize = 1000
    val prover = new BatchAVLProver[T, Blake2b256Unsafe](KL, None)
    val digest = prover.digest
    val keyValues = (0 until TreeSize) map { i =>
      val aValue = Keccak256(i.toString.getBytes)
      (ADKey @@ aValue.take(KL), ADValue @@ aValue)
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))

    val pf = prover.generateProof()

    val verifier = new BatchAVLVerifier[T, Blake2b256Unsafe](digest, pf, KL, None)
    val infinityLeaf: VerifierNodes[T] = verifier.extractFirstNode {
      case _: VerifierLeaf[T] => true
      case _ => false
    }.get
    val nonInfiniteLeaf: VerifierNodes[T] => Boolean = {
      case l: VerifierLeaf[T] => !(l.label sameElements infinityLeaf.label)
      case _ => false
    }

    (0 until TreeSize) foreach { i =>
      val aValue = Keccak256(i.toString.getBytes)
      verifier.performOneOperation(Insert(ADKey @@ aValue.take(KL), ADValue @@aValue))
    }
    //extract all leafs
    val allLeafs = verifier.extractNodes(nonInfiniteLeaf)
    allLeafs.get.length shouldBe TreeSize
    //First extracted leaf should be smallest
    val ordering: (Array[Byte], Array[Byte]) => Boolean = (a, b) => ByteArray.compare(a, b) > 0
    val smallestKey = keyValues.map(_._1).sortWith(ordering).last
    val minLeaf = verifier.extractFirstNode(nonInfiniteLeaf).get.asInstanceOf[VerifierLeaf[T]]
    minLeaf.key shouldEqual smallestKey
  }

  property("BatchAVLVerifier: extractFirstNode") {
    //todo: implement
  }

  property("Batch of lookups") {
    //prepare tree
    val prover = new BatchAVLProver[T, HF](KL, None)
    (0 until 1000) foreach { i =>
      val aValue = Keccak256(i.toString.getBytes)
      prover.performOneOperation(Insert(ADKey @@aValue.take(KL),ADValue @@ aValue))
    }
    prover.generateProof()
    val digest = prover.digest

    forAll(smallInt) { numberOfLookups: Int =>
      val currentMods = (0 until numberOfLookups).map(_ => randomKey(KL)).map(k => Lookup(k))

      currentMods foreach (m => prover.performOneOperation(m))
      val pf = prover.generateProof()

      val verifier = new BatchAVLVerifier[T, HF](digest, pf, KL, None)
      currentMods foreach (m => verifier.performOneOperation(m).get)
      prover.digest shouldEqual verifier.digest.get
    }
    prover.checkTree(true)
  }

  property("Tree without fixed value length") {
    val prover = new BatchAVLProver[T, HF](KL, None)
    var digest = prover.digest

    forAll { valueLength: Short =>
      whenever(valueLength >= 0) {
        val aKey = Random.randomBytes(KL)
        val aValue = Random.randomBytes(valueLength)
        val currentMods = Seq(Insert(ADKey @@ aKey, ADValue @@ aValue))

        currentMods foreach (m => prover.performOneOperation(m))
        val pf = prover.generateProof()

        val verifier = new BatchAVLVerifier[T, HF](digest, pf, KL, None)
        currentMods foreach (m => verifier.performOneOperation(m))
        digest = verifier.digest.get

        prover.digest shouldEqual digest
      }
    }
    prover.checkTree(true)
  }

  property("Modifications for different key and value length") {
    Try {
      forAll { (aKey: Array[Byte], aValue: Array[Byte]) =>
        val KL = aKey.length
        val VL = aValue.length
        whenever(KL > 0 && VL > 0 && !aKey.forall(_ equals (-1: Byte)) && !aKey.forall(_ equals (0: Byte))) {
          val prover = new BatchAVLProver[T, HF](KL, Some(VL))
          val m = Insert(ADKey @@ aKey, ADValue @@ aValue)

          val digest = prover.digest
          prover.performOneOperation(m)
          val pf = prover.generateProof()
          prover.digest

          val verifier = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL))
          verifier.performOneOperation(m)
          if (verifier.digest.isEmpty) {
            println("problematic key: " + aKey.mkString("-"))
            println("problematic value: " + Base58.encode(aValue))
          }
          verifier.digest.isDefined shouldBe true
          prover.digest shouldEqual verifier.digest.get

          val lookup = Lookup(ADKey @@ aKey)
          prover.performOneOperation(lookup)
          val pr = prover.generateProof()
          val vr = new BatchAVLVerifier[T, HF](prover.digest, pr, KL, Some(VL))
          vr.performOneOperation(lookup).get.get shouldEqual aValue

          val nonExistinglookup = Lookup(randomKey(KL))
          prover.performOneOperation(nonExistinglookup)
          val pr2 = prover.generateProof()
          val vr2 = new BatchAVLVerifier[T, HF](prover.digest, pr2, KL, Some(VL))
          vr2.performOneOperation(nonExistinglookup).get shouldBe None
        }
      }
    }.recoverWith {
      case e =>
        e.printStackTrace()
        Failure(e)
    }.get
  }

  property("Lookups") {
    val prover = new BatchAVLProver[T, HF](KL, Some(VL))
    forAll(kvSeqGen) { kvSeq =>
      val insertNum = Math.min(3, kvSeq.length)
      val toInsert = kvSeq.take(insertNum)
      toInsert.foreach { ti =>
        prover.performOneOperation(Insert(ti._1, ti._2))
      }
      prover.generateProof()
      val lookups = kvSeq.map(kv => Lookup(kv._1))

      lookups.foreach(l => prover.performOneOperation(l))
      val pr = prover.generateProof()

      val vr = new BatchAVLVerifier[T, HF](prover.digest, pr, KL, Some(VL))
      kvSeq.foreach { kv =>
        vr.performOneOperation(Lookup(kv._1)).get match {
          case Some(v) =>
            toInsert.find(_._1 sameElements kv._1).get._2 shouldEqual v
          case None =>
            toInsert.exists(_._1 sameElements kv._1) shouldBe false
        }
      }
    }
  }


  property("Usage as authenticated set") {
    val SetVL = Some(0)
    val prover = new BatchAVLProver[T, HF](KL, SetVL)
    var digest = prover.digest
    //    val valueToInsert:Array[Byte] = Array.fill(SetVL)(0.toByte)
    val valueToInsert: Array[Byte] = Array.empty

    forAll(kvGen) { case (aKey, _) =>
      whenever(prover.unauthenticatedLookup(aKey).isEmpty) {
        val m = Insert(aKey, ADValue @@ valueToInsert)
        prover.performOneOperation(m)
        val pf = prover.generateProof()
        prover.digest

        val verifier = new BatchAVLVerifier[T, HF](digest, pf, KL, SetVL)
        verifier.performOneOperation(m)
        digest = verifier.digest.get
        prover.digest shouldEqual digest
      }
    }

  }

  property("Long updates") {
    val prover = new BatchAVLProver[T, HF](KL, Some(VL))
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val oldValue: Long = prover.unauthenticatedLookup(aKey).map(Longs.fromByteArray).getOrElse(0L)
      val delta = Math.abs(Longs.fromByteArray(aValue))
      whenever(Try(Math.addExact(oldValue, delta)).isSuccess) {

        val m = UpdateLongBy(aKey, delta)

        prover.performOneOperation(m).get.getOrElse(0L) shouldBe oldValue
        val pf = prover.generateProof()

        val verifier = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL))
        verifier.performOneOperation(m)
        digest = verifier.digest.get
        prover.digest shouldEqual digest
        prover.unauthenticatedLookup(aKey) match {
          case Some(v) => require(delta + oldValue == Longs.fromByteArray(v))
          case None => require(delta + oldValue == 0)
        }
      }
    }
    prover.checkTree(true)
  }


  property("zero-mods verification on empty tree") {
    val p = new BatchAVLProver[T, HF](KL, Some(VL))
    p.checkTree()
    val digest = p.digest
    val pf = p.generateProof()
    p.checkTree(true)
    val v = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL), Some(0), Some(0))
    v.digest match {
      case Some(d) =>
        require(d sameElements digest, "wrong digest for zero-mods")
      case None =>
        throw new Error("zero-mods verification failed to construct tree")
    }
  }

  property("conversion to byte and back") {
    // There is no way to test this without building a tree with at least 2^88 leaves,
    // so we resort to a very basic test
    val p = new BatchAVLProver[T, HF](KL, Some(VL))
    val digest = p.digest
    for (i <- 0 to 255) {
      digest(digest.length - 1) = i.toByte
      val rootNodeHeight: Int = digest.last & 0xff
      rootNodeHeight shouldBe i
    }
  }


  property("various verifier fails") {
    val p = new BatchAVLProver[T, HF](KL, Some(VL))

    p.checkTree()
    for (i <- 0 until 1000) {
      require(p.performOneOperation(Insert(randomKey(KL), randomValue(VL))).isSuccess, "failed to insert")
      p.checkTree()
    }
    p.generateProof()

    var digest = p.digest
    for (i <- 0 until 50)
      require(p.performOneOperation(Insert(randomKey(KL), randomValue(VL))).isSuccess, "failed to insert")

    var pf = p.generateProof()

    // see if the proof for 50 mods will be allowed when we permit only 2
    var v = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL), Some(2), Some(0))
    require(v.digest.isEmpty, "Failed to reject too long a proof")

    // see if wrong digest will be allowed
    v = new BatchAVLVerifier[T, HF](ADDigest @@ Random.randomBytes(KL), pf, KL, Some(VL), Some(50), Some(0))
    require(v.digest.isEmpty, "Failed to reject wrong digest")

    for (i <- 0 until 10) {
      digest = p.digest
      for (i <- 0 until 8)
        require(p.performOneOperation(Insert(randomKey(KL), randomValue(8))).isSuccess, "failed to insert")

      v = new BatchAVLVerifier[T, HF](digest, p.generateProof(), KL, Some(VL), Some(8), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      // Try 5 inserts that do not match -- with overwhelming probability one of them will go to a leaf
      // that is not in the conveyed tree, and verifier will complain
      for (i <- 0 until 5)
        v.performOneOperation(Insert(randomKey(KL), randomValue(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed, because of a missing leaf")

      digest = p.digest
      val key = randomKey(KL)
      p.performOneOperation(Insert(ADKey @@ key, randomValue(8)))
      pf = p.generateProof()
      p.checkTree()

      // Change the direction of the proof and make sure verifier fails
      pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
      v = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL), Some(1), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      v.performOneOperation(Insert(key, randomValue(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed, because of the wrong direction")

      // Change the key by a large amount -- verification should fail with overwhelming probability
      // because there are 1000 keys in the tree
      // First, change the proof back to be correct
      pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
      val oldKey = key(0)
      key(0) = (key(0) ^ (1 << 7)).toByte
      v = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL), Some(1), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      v.performOneOperation(Insert(key, randomValue(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed because of the wrong key")
      // put the key back the way it should be, because otherwise it's messed up in the prover tree
      key(0) = (key(0) ^ (1 << 7)).toByte
    }
  }

  property("remove single random element from a large set") {

    val minSetSize = 10000
    val maxSetSize = 100000

    forAll(Gen.choose(minSetSize, maxSetSize), Arbitrary.arbBool.arbitrary) { case (cnt, generateProof) =>
      whenever(cnt > minSetSize) {
        var keys = IndexedSeq[ADKey]()
        val prover = new BatchAVLProver[T, HF](KL, Some(VL))

        (1 to cnt) foreach { _ =>
          val key:ADKey = randomKey(KL)
          val value = randomValue(VL)

          keys = key +: keys

          prover.performOneOperation(Insert(key, value)).isSuccess shouldBe true
          prover.unauthenticatedLookup(key).isDefined shouldBe true
        }

        if (generateProof) prover.generateProof()

        val keyPosition = scala.util.Random.nextInt(keys.length)
        val rndKey = keys(keyPosition)

        prover.unauthenticatedLookup(rndKey).isDefined shouldBe true
        val removalResult = prover.performOneOperation(Remove(rndKey))
        removalResult.isSuccess shouldBe true

        if (keyPosition > 0) {
          prover.performOneOperation(Remove(keys.head)).isSuccess shouldBe true
        }

        keys = keys.tail.filterNot(_.sameElements(rndKey))

        val shuffledKeys = scala.util.Random.shuffle(keys)
        shuffledKeys.foreach { k =>
          prover.performOneOperation(Remove(k)).isSuccess shouldBe true
        }
      }
    }
  }

  property("successful modifications") {
    val p = new BatchAVLProver[T, HF](KL, Some(VL))

    val numMods = 5000

    val deletedKeys = new scala.collection.mutable.ArrayBuffer[ADKey]

    val keysAndVals = new scala.collection.mutable.ArrayBuffer[(ADKey, ADValue)]

    var i = 0
    var numInserts = 0
    var numModifies = 0
    var numDeletes = 0
    var numNonDeletes = 0
    var numFailures = 0

    while (i < numMods) {
      val digest = p.digest
      val n = randomInt(100)
      val j = i + n
      var numCurrentDeletes = 0
      val currentMods = new scala.collection.mutable.ArrayBuffer[Operation](n)
      while (i < j) {
        if (keysAndVals.isEmpty || randomInt(2) == 0) {
          // with prob .5 insert a new one, with prob .5 update or delete an existing one
          if (keysAndVals.nonEmpty && randomInt(10) == 0) {
            // with probability 1/10 cause a fail by inserting already existing
            val j = Random.randomBytes(3)
            val index = randomInt(keysAndVals.size)
            val key = keysAndVals(index)._1
            require(p.performOneOperation(Insert(key, randomValue(VL))).isFailure, "prover succeeded on inserting a value that's already in tree")
            p.checkTree()
            require(p.unauthenticatedLookup(key).get sameElements keysAndVals(index)._2, "value changed after duplicate insert") // check insert didn't do damage
            numFailures += 1
          }
          else {
            val key = randomKey(KL)
            val newVal = randomValue(VL)
            keysAndVals += ((key, newVal))
            val mod = Insert(key, newVal)
            currentMods += mod
            require(p.performOneOperation(mod).isSuccess, "prover failed to insert")
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
              // with probability 1/10 cause a fail by modifying a non-existing key
              val key = randomKey(KL)
              require(p.performOneOperation(Update(key, randomValue(8))).isFailure, "prover updated a nonexistent value")
              p.checkTree()
              require(p.unauthenticatedLookup(key).isEmpty, "a nonexistent value appeared after an update") // check update didn't do damage
              numFailures += 1
            }
            else {
              val index = randomInt(keysAndVals.size)
              val key = keysAndVals(index)._1
              val newVal = randomValue(8)
              val mod = Update(key, newVal)
              currentMods += mod
              p.performOneOperation(mod).get
              keysAndVals(index) = (key, newVal)
              require(p.unauthenticatedLookup(key).get sameElements newVal, "wrong value after update") // check update
              numModifies += 1
            }
          } else {
            // delete
            if (randomInt(10) == 0) {
              // with probability 1/10 remove a non-existing one but without failure -- shouldn't change the tree
              val key = randomKey(KL)
              val mod = RemoveIfExists(key)
              val d = p.digest
              currentMods += mod
              require(p.performOneOperation(mod).isSuccess, "prover failed when it should have done nothing")
              require(d sameElements p.digest, "Tree changed when it shouldn't have")
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
              require(p.performOneOperation(mod).isSuccess, "failed ot delete")
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

      val pf = p.generateProof()
      p.checkTree(true)

      val v = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL), Some(n), Some(numCurrentDeletes))
      v.digest match {
        case None =>
          throw new Error("Verification failed to construct the tree")
        case Some(d) =>
          require(d sameElements digest, "Built tree with wrong digest") // Tree built successfully
      }

      currentMods foreach (m => v.performOneOperation(m))
      v.digest match {
        case None =>
          throw new Error("Verification failed")
        case Some(d) =>
          require(d sameElements p.digest, "Tree has wrong digest after verification")
      }
    }

    // Check that all the inserts, deletes, and updates we did actually stayed
    deletedKeys foreach (k => require(p.unauthenticatedLookup(k).isEmpty, "Key that was deleted is still in the tree"))
    keysAndVals foreach (pair => require(p.unauthenticatedLookup(pair._1).get sameElements pair._2, "Key has wrong value"))
  }

  property("Persistence AVL batch prover") {
    val storage = new VersionedAVLStorageMock[T]
    val p = new BatchAVLProver[T, HF](KL, Some(VL))
    val prover = PersistentBatchAVLProver.create[T, HF](p, storage, paranoidChecks = true).get
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val m = Insert(aKey, aValue)
      prover.performOneOperation(m)
      val pf = prover.generateProofAndUpdateStorage()

      val verifier = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL))
      verifier.digest.get
      verifier.performOneOperation(m)

      prover.digest should not equal digest
      prover.digest shouldEqual verifier.digest.get

      prover.rollback(digest).isSuccess shouldBe true
      prover.digest shouldEqual digest
      prover.performOneOperation(m)
      prover.generateProofAndUpdateStorage()
      digest = prover.digest
    }

    val prover2 = PersistentBatchAVLProver.create(new BatchAVLProver[T, HF](KL, Some(VL)), storage, paranoidChecks = true).get
    prover2.digest shouldEqual prover.digest
  }

  property("Updates with and without batching should lead to the same tree") {
    val tree = new AVLTree(KL)
    var digest = tree.rootHash()
    val oldProver = new LegacyProver(tree)
    val newProver = new BatchAVLProver[T, HF](KL, Some(VL))
    require(newProver.digest startsWith oldProver.rootHash)
    require(newProver.digest.length == oldProver.rootHash.length + 1)

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Seq(Insert(aKey, aValue))
      oldProver.applyBatchSimple(currentMods) match {
        case bss: BatchSuccessSimple =>
          new LegacyVerifier(digest).verifyBatchSimple(currentMods, bss) shouldBe true
        case bf: BatchFailure => throw bf.error
      }

      currentMods foreach (m => newProver.performOneOperation(m))
      val pf = newProver.generateProof()

      digest = oldProver.rootHash
      require(newProver.digest startsWith digest)
      require(newProver.digest.length == oldProver.rootHash.length + 1)
    }
    newProver.checkTree(true)
  }

  property("Verifier should calculate the same digest") {
    val prover = new BatchAVLProver[T, HF](KL, Some(VL))
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Seq(Insert(aKey, aValue))

      currentMods foreach (m => prover.performOneOperation(m))
      val pf = prover.generateProof()

      val verifier = new BatchAVLVerifier[T, HF](digest, pf, KL, Some(VL))
      currentMods foreach (m => verifier.performOneOperation(m))
      digest = verifier.digest.get

      prover.digest shouldEqual digest
    }
    prover.checkTree(true)
  }


  lazy val kvGen: Gen[(ADKey, ADValue)] = for {
    key <- Gen.listOfN(KL, Arbitrary.arbitrary[Byte]).map(_.toArray) suchThat
      (k => !(k sameElements Array.fill(KL)(-1: Byte)) && !(k sameElements Array.fill(KL)(0: Byte)) && k.length == KL)
    value <- Gen.listOfN(VL, Arbitrary.arbitrary[Byte]).map(_.toArray)
  } yield (ADKey @@ key, ADValue @@ value)

  lazy val kvSeqGen: Gen[Seq[(ADKey, ADValue)]] = Gen.nonEmptyListOf(kvGen)

}
