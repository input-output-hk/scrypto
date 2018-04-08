package scorex.crypto.authds.avltree.batch

import com.google.common.primitives.Longs
import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.legacy.avltree.AVLTree
import scorex.crypto.authds.{ADDigest, ADKey, ADValue, TwoPartyTests}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, _}
import scorex.utils.{ByteArray, Random}

import scala.util.Random.{nextInt => randomInt}
import scala.util.{Failure, Try}

class AVLBatchSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val InitialTreeSize = 1000
  val KL = 26
  val VL = 8
  val HL = 32
  type D = Digest32
  type HF = Blake2b256.type

  def randomKey(size: Int = 32): ADKey = ADKey @@ Random.randomBytes(size)

  def randomValue(size: Int = 32): ADValue = ADValue @@ Random.randomBytes(size)

  private def generateProver(size: Int = InitialTreeSize): BatchAVLProver[D, HF] = {
    val prover = new BatchAVLProver[D, HF](KL, None)
    val keyValues = (0 until size) map { i =>
      (ADKey @@ Blake2b256(i.toString.getBytes).take(KL), ADValue @@ (i.toString.getBytes))
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))
    prover.generateProof()
    prover
  }

  property("return removed leafs and internal nodes for small tree") {
    /**
      * manual check, that correct leafs and internal nodes where deleted
      * ______________top(V9WU)                                top2(5VjC)
      * ________________/   \                                      /   \
      * NegativeInfinity    right(5VjC)       =>   NegativeInfinity     Leaf1(5VjC)
      * ____________________/     \
      * __________Leaf0(V9WU)      Leaf1(5VjC)
      **/
    val prover = generateProver(2)
    val top = prover.topNode.asInstanceOf[InternalProverNode[D]] // V9WUMj6PYcMMgi8FNYELQPrzHbQs15HYwMi
    val negativeInfinity = top.left.asInstanceOf[ProverLeaf[D]] // 11111111111111111111111111
    val right = top.right.asInstanceOf[InternalProverNode[D]] // 5VjCEAdtJfWHnXZau2oxogRg2xESXgF68sUm
    val leaf0 = right.left.asInstanceOf[ProverLeaf[D]] // V9WUMj6PYcMMgi8FNYELQPrzHbQs15HYwMi
    val leaf1 = right.right.asInstanceOf[ProverLeaf[D]] // 5VjCEAdtJfWHnXZau2oxogRg2xESXgF68sUm

    val all = Seq(leaf1, top, right, leaf0, negativeInfinity)
    all.foreach(n => prover.contains(n) shouldBe true)
    val removedManual = all.tail

    prover.performOneOperation(Remove(leaf0.key))
    prover.performOneOperation(Lookup(leaf1.key))
    val removed = prover.removedNodes()
    prover.generateProof()

    // Top, Right and Leaf0 are not on the path any more, NegativeInfinity.newNextLeafKey changed.
    // Leaf1 is not affected
    removed.length shouldBe removedManual.length
    removedManual.foreach(n => removed.exists(_.label sameElements n.label) shouldBe true)
  }

  property("return removed leafs and internal nodes") {
    val prover = generateProver()
    forAll(kvSeqGen) { kvSeq =>
      val mSize = Math.min(10, kvSeq.length)
      val toInsert = kvSeq.take(mSize).map(ti => Insert(ti._1, ti._2))
      val toRemove = (0 until mSize).flatMap(i => prover.randomWalk(new scala.util.Random(i))).map(kv => Remove(kv._1))
      val modifications = toInsert ++ toRemove
      modifications.foreach(ti => prover.performOneOperation(ti))
      val removed = prover.removedNodes()
      removed.length should be > mSize
      toRemove.foreach(tr => removed.exists(_.key sameElements tr.key) shouldBe true)

      val modifyingProof = prover.generateProof()
      prover.removedNodes().isEmpty shouldBe true
    }
  }


  property("proof generation without tree modification") {
    val prover = generateProver()
    forAll(kvSeqGen) { kvSeq =>
      val insertNum = Math.min(10, kvSeq.length)
      val toInsert = kvSeq.take(insertNum).map(ti => Insert(ti._1, ti._2))
      val toRemove = (0 until insertNum).flatMap(i => prover.randomWalk(new scala.util.Random(i))).map(kv => Remove(kv._1))
      val modifications = toInsert ++ toRemove
      val initialDigest = prover.digest

      // generate proof without tree modification
      val nonModifyingProof = prover.generateProofForOperations(modifications)
      prover.digest shouldEqual initialDigest
      toInsert.foreach(ti => prover.unauthenticatedLookup(ti.key) shouldBe None)
      toRemove.foreach(ti => prover.unauthenticatedLookup(ti.key).isDefined shouldBe true)
      val verifier = new BatchAVLVerifier[D, HF](initialDigest, nonModifyingProof, KL, None)
      modifications foreach (m => verifier.performOneOperation(m).get)

      // generate another proof without tree modification
      val toInsert2 = toInsert.map(ti => Insert(ADKey @@ Blake2b256(ti.key), ADValue @@ Blake2b256(ti.value)))
      val toRemove2 = (0 until insertNum + 1).flatMap(i => prover.randomWalk(new scala.util.Random(i))).map(kv => Remove(kv._1))
      val modifications2 = toRemove2
      val nonModifyingProof2 = prover.generateProofForOperations(modifications2)
      prover.digest shouldEqual initialDigest

      // modify tree and generate proof
      modifications.foreach(ti => prover.performOneOperation(ti))
      val modifyingProof = prover.generateProof()
      prover.digest shouldEqual verifier.digest.get
      Base58.encode(prover.digest) should not be Base58.encode(initialDigest)
      modifyingProof shouldEqual nonModifyingProof
      toInsert.foreach(ti => prover.unauthenticatedLookup(ti.key) shouldBe Some(ti.value))
      toRemove.foreach(ti => prover.unauthenticatedLookup(ti.key) shouldBe None)
    }
  }

  property("randomWalk") {
    val prover = generateProver()

    forAll { seed: Long =>
      val e1 = prover.randomWalk(new scala.util.Random(seed))
      val e2 = prover.randomWalk(new scala.util.Random(seed))
      e1.get._1 shouldEqual e2.get._1
      e1.get._2 shouldEqual e2.get._2
    }
  }

  property("unauthenticatedLookup") {
    val p = new BatchAVLProver[Digest32, HF](keyLength = 8, valueLengthOpt = None)

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
    val prover = new BatchAVLProver[D, HF](KL, None)
    val digest = prover.digest
    val keyValues = (0 until InitialTreeSize) map { i =>
      val aValue = Keccak256(i.toString.getBytes)
      (ADKey @@ aValue.take(KL), ADValue @@ aValue)
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))

    val pf = prover.generateProof()

    val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, None)
    val infinityLeaf: VerifierNodes[D] = verifier.extractFirstNode {
      case _: VerifierLeaf[D] => true
      case _ => false
    }.get
    val nonInfiniteLeaf: VerifierNodes[D] => Boolean = {
      case l: VerifierLeaf[D] => !(l.label sameElements infinityLeaf.label)
      case _ => false
    }

    (0 until InitialTreeSize) foreach { i =>
      val aValue = Keccak256(i.toString.getBytes)
      verifier.performOneOperation(Insert(ADKey @@ aValue.take(KL), ADValue @@ aValue))
    }
    //extract all leafs
    val allLeafs = verifier.extractNodes(nonInfiniteLeaf)
    allLeafs.get.length shouldBe InitialTreeSize
    //First extracted leaf should be smallest
    val ordering: (Array[Byte], Array[Byte]) => Boolean = (a, b) => ByteArray.compare(a, b) > 0
    val smallestKey = keyValues.map(_._1).sortWith(ordering).last
    val minLeaf = verifier.extractFirstNode(nonInfiniteLeaf).get.asInstanceOf[VerifierLeaf[D]]
    minLeaf.key shouldEqual smallestKey
  }

  property("BatchAVLVerifier: extractFirstNode") {
    //todo: implement
  }

  property("Batch of lookups") {
    //prepare tree
    val prover = generateProver()
    val digest = prover.digest

    forAll(smallInt) { numberOfLookups: Int =>
      val currentMods = (0 until numberOfLookups).map(_ => randomKey(KL)).map(k => Lookup(k))

      currentMods foreach (m => prover.performOneOperation(m))
      val pf = prover.generateProof()

      val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, None)
      currentMods foreach (m => verifier.performOneOperation(m).get)
      prover.digest shouldEqual verifier.digest.get
    }
    prover.checkTree(true)
  }

  property("Tree without fixed value length") {
    val prover = new BatchAVLProver[D, HF](KL, None)
    var digest = prover.digest

    forAll { valueLength: Short =>
      whenever(valueLength >= 0) {
        val aKey = Random.randomBytes(KL)
        val aValue = Random.randomBytes(valueLength)
        val currentMods = Seq(Insert(ADKey @@ aKey, ADValue @@ aValue))

        currentMods foreach (m => prover.performOneOperation(m))
        val pf = prover.generateProof()

        val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, None)
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
          val prover = new BatchAVLProver[D, HF](KL, Some(VL))
          val m = Insert(ADKey @@ aKey, ADValue @@ aValue)

          val digest = prover.digest
          prover.performOneOperation(m)
          val pf = prover.generateProof()
          prover.digest

          val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL))
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
          val vr = new BatchAVLVerifier[D, HF](prover.digest, pr, KL, Some(VL))
          vr.performOneOperation(lookup).get.get shouldEqual aValue

          val nonExistinglookup = Lookup(randomKey(KL))
          prover.performOneOperation(nonExistinglookup)
          val pr2 = prover.generateProof()
          val vr2 = new BatchAVLVerifier[D, HF](prover.digest, pr2, KL, Some(VL))
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
    val prover = new BatchAVLProver[D, HF](KL, Some(VL))
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

      val vr = new BatchAVLVerifier[D, HF](prover.digest, pr, KL, Some(VL))
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
    val prover = new BatchAVLProver[D, HF](KL, SetVL)
    var digest = prover.digest
    //    val valueToInsert:Array[Byte] = Array.fill(SetVL)(0.toByte)
    val valueToInsert: Array[Byte] = Array.empty

    forAll(kvGen) { case (aKey, _) =>
      whenever(prover.unauthenticatedLookup(aKey).isEmpty) {
        val m = Insert(aKey, ADValue @@ valueToInsert)
        prover.performOneOperation(m)
        val pf = prover.generateProof()
        prover.digest

        val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, SetVL)
        verifier.performOneOperation(m)
        digest = verifier.digest.get
        prover.digest shouldEqual digest
      }
    }

  }

  property("Long updates") {
    val prover = new BatchAVLProver[D, HF](KL, Some(VL))
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val oldValue: Long = prover.unauthenticatedLookup(aKey).map(Longs.fromByteArray).getOrElse(0L)
      val delta = Math.abs(Longs.fromByteArray(aValue))
      whenever(Try(Math.addExact(oldValue, delta)).isSuccess) {

        val m = UpdateLongBy(aKey, delta)

        prover.performOneOperation(m).get.getOrElse(0L) shouldBe oldValue
        val pf = prover.generateProof()

        val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL))
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
    val p = new BatchAVLProver[D, HF](KL, Some(VL))
    p.checkTree()
    val digest = p.digest
    val pf = p.generateProof()
    p.checkTree(true)
    val v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(0), Some(0))
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
    val p = new BatchAVLProver[D, HF](KL, Some(VL))
    val digest = p.digest
    for (i <- 0 to 255) {
      digest(digest.length - 1) = i.toByte
      val rootNodeHeight: Int = digest.last & 0xff
      rootNodeHeight shouldBe i
    }
  }


  property("various verifier fails") {
    val p = new BatchAVLProver[D, HF](KL, Some(VL))

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
    var v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(2), Some(0))
    require(v.digest.isEmpty, "Failed to reject too long a proof")

    // see if wrong digest will be allowed
    v = new BatchAVLVerifier[D, HF](ADDigest @@ Random.randomBytes(KL), pf, KL, Some(VL), Some(50), Some(0))
    require(v.digest.isEmpty, "Failed to reject wrong digest")

    for (i <- 0 until 10) {
      digest = p.digest
      for (i <- 0 until 8)
        require(p.performOneOperation(Insert(randomKey(KL), randomValue(8))).isSuccess, "failed to insert")

      v = new BatchAVLVerifier[D, HF](digest, p.generateProof(), KL, Some(VL), Some(8), Some(0))
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
      v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(1), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      v.performOneOperation(Insert(key, randomValue(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed, because of the wrong direction")

      // Change the key by a large amount -- verification should fail with overwhelming probability
      // because there are 1000 keys in the tree
      // First, change the proof back to be correct
      pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
      val oldKey = key(0)
      key(0) = (key(0) ^ (1 << 7)).toByte
      v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(1), Some(0))
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
        val prover = new BatchAVLProver[D, HF](KL, Some(VL))

        (1 to cnt) foreach { _ =>
          val key: ADKey = randomKey(KL)
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
    val p = new BatchAVLProver[D, HF](KL, Some(VL))

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

      val v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(n), Some(numCurrentDeletes))
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
    val storage = new VersionedAVLStorageMock[D]
    val p = new BatchAVLProver[D, HF](KL, Some(VL))
    val prover = PersistentBatchAVLProver.create[D, HF](p, storage, paranoidChecks = true).get
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val m = Insert(aKey, aValue)
      prover.performOneOperation(m)
      val pf = prover.generateProofAndUpdateStorage()

      val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL))
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

    val prover2 = PersistentBatchAVLProver.create(new BatchAVLProver[D, HF](KL, Some(VL)), storage, paranoidChecks = true).get
    prover2.digest shouldEqual prover.digest
  }

  property("Updates with and without batching should lead to the same tree") {
    val tree = new AVLTree(KL)
    var digest = tree.rootHash()
    val oldProver = new LegacyProver(tree)
    val newProver = new BatchAVLProver[D, HF](KL, Some(VL))
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
    val prover = new BatchAVLProver[D, HF](KL, Some(VL))
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Seq(Insert(aKey, aValue))

      currentMods foreach (m => prover.performOneOperation(m))
      val pf = prover.generateProof()

      val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL))
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
