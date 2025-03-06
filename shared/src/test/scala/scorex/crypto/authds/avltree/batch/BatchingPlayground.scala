package scorex.crypto.authds.avltree.batch

import scorex.utils.Longs
import org.scalatest.matchers.should.Matchers
import scorex.crypto.authds.legacy.avltree.{AVLModifyProof, AVLTree}
import scorex.crypto.authds.{ADDigest, ADKey, ADValue}
import scorex.crypto.hash.{Blake2b256, Digest32, Sha256}
import scorex.utils.Random

import scala.util.Success

object BatchingPlayground extends App with BatchTestingHelpers with Matchers {

  /**
    * Return time in milliseconds and execution result
    */
  def time[R](block: => R): (Long, R) = {
    val t0 = System.nanoTime()
    val result = block // call-by-name
    val t1 = System.nanoTime()
    ((t1 - t0) / 1000000, result)
  }

  //smallDeleteTest

  //  lookupTest()
  //batchingSelfTest

  //deleteProofSizeTest

  //memoryTestWithBatching
  //memoryTestNoBatching
  //timeBenchmarksNew
  //timeBenchmarksOld
  //spaceBenchmarks
  //lookupBenchmark()
  //  testReadme
  //removedNodesBenchmark
  //removedNodesBenchmark()

  testReadme()

  def removedNodesBenchmark(startTreeSize: Int = 10000,
                            toRemoveSize: Int = 2000,
                            toInsertSize: Int = 2000): Unit = {
    val iterations = 50
    var toRemoveTotal: Long = 0
    var proofGenerationTotal: Long = 0
    var performOperationTotal: Long = 0
    val (prover, elements) = generateProver(startTreeSize)

    println(s"tree size,removed leafs,removed nodes,removedNodesTime(ms),nonModifyingproofGenerationTime(ms),proofGenerationTime(ms),performOperationsTime(ms)")
    (0 until iterations).foreach { i =>
      System.gc()
      val toRemove = elements.slice(i * toRemoveSize, (i + 1) * toRemoveSize).map(e => Remove(e._1))
      val toInsert = (0 until toInsertSize).map(j => Sha256(s"$i-$j"))
        .map(k => Insert(ADKey @@@ k, ADValue @@ k.take(8)))
      val treeSize = startTreeSize + i * (toInsert.length - toRemove.length)
      val oldTop = prover.topNode
      val mods = toRemove ++ toInsert

      val (nonModifyingTime, nonModifyingProof) =  time {
        prover.generateProofForOperations(mods).get._1
      }

      val (performOperationsTime, _) = time {
        mods.foreach(op => prover.performOneOperation(op).get)
      }
      val (removedNodesTime, removedNodes) = time {
        prover.removedNodes()
      }
      val removedNodesLength = removedNodes.length
      val (proofGenerationTime, proofBytes) = time {
        prover.generateProof()
      }

      nonModifyingProof shouldEqual proofBytes
      checkTree(prover, oldTop, removedNodes)
      toRemoveTotal += removedNodesTime
      proofGenerationTotal += proofGenerationTime
      performOperationTotal += performOperationsTime
      println(s"$treeSize,$toRemoveSize,$removedNodesLength,$removedNodesTime,$nonModifyingTime,$proofGenerationTime,$performOperationsTime")
    }
    println(s"Average times for startTreeSize=$startTreeSize,toRemoveSize=$toRemoveSize,toInsertSize=$toInsertSize:" +
      s" toRemove=${toRemoveTotal / iterations}, proofGeneration=${proofGenerationTotal / iterations}, performOperation=${performOperationTotal / iterations}")
    // Average times for startTreeSize=10000000,toRemoveSize=3000,toInsertSize=3000: toRemove=71, proofGeneration=85, performOperation=44
  }

  def lookupBenchmark(): Unit = {
    val prover = new BatchAVLProver[D, HF](KL, Some(VL))
    println(s"modifyingLookupProoflength,modifyingLookupTime,modifyingLookupVerificationTime,lookupProoflength,lookupTime,lookupVerificationTime")

    val ElementsToInsert = 100000
    val elements = (0 until ElementsToInsert)
      .map(i => Sha256(i.toString))
      .map(k => (ADKey @@@ k, ADValue @@ k.take(8)))

    elements.foreach(e => prover.performOneOperation(Insert(e._1, e._2)))
    prover.generateProof()
    val digest = prover.digest
    val lookups = elements.map(e => Lookup(e._1))
    val oldLookups = lookups.map(l => ModifyingLookup(l.key))

    val (lookupTime, lookupProof) = time {
      lookups.foreach(l => prover.performOneOperation(l))
      prover.generateProof()
    }
    val vr = new BatchAVLVerifier[D, HF](prover.digest, lookupProof, KL, Some(VL))
    val (lookupVerificationTime, _) = time(
      lookups.map(lookup => lookup.key -> vr.performOneOperation(lookup).get))
    // modifying lookups

    val digest2 = prover.digest
    val (oldLookupTime, oldLookupProof) = time {
      oldLookups.foreach(ol => prover.performOneOperation(ol))
      prover.generateProof()
    }
    val verifier = new BatchAVLVerifier[D, HF](digest2, oldLookupProof, KL, Some(VL))
    val (oldLookupVerificationTime, _) = time {
      oldLookups.foreach(ol => verifier.performOneOperation(ol))
    }

    println(s"${oldLookupProof.length},$oldLookupTime,$oldLookupVerificationTime," +
      s"${lookupProof.length},$lookupTime,$lookupVerificationTime")

  }

  def lookupTest() = {
    val kl = 4
    val vl = 7

    val p = new BatchAVLProver[D, HF](keyLength = kl, valueLengthOpt = Some(vl))

    val key1 = ADKey @@ Sha256("1").take(kl)
    val key2 = ADKey @@ Sha256("2").take(kl)
    val key3 = ADKey @@ Sha256("3").take(kl)
    val key4 = ADKey @@ Sha256("4").take(kl)
    val key5 = ADKey @@ Sha256("5").take(kl)
    val key6 = ADKey @@ Sha256("6").take(kl)
    val key7 = ADKey @@ Sha256("7").take(kl)

    println("k1: " + arrayToString(key1))
    println("k2: " + arrayToString(key2))
    println("k3: " + arrayToString(key3))

    val v1 = ADValue @@ Sha256("1").take(vl)
    val v2 = ADValue @@ Sha256("2").take(vl)

    val i1 = Insert(key1, v1)
    val i2 = Insert(key2, v2)

    p.performOneOperation(i1)
    p.performOneOperation(i2)
    p.generateProof()

    val l1 = Lookup(key1)
    val l2 = Lookup(key2)
    val l3 = Lookup(key3)

    val pr = {
      Seq(l1, l2, l3).foreach(l => p.performOneOperation(l))
      p.generateProof()
    }

    val vr = new BatchAVLVerifier[D, HF](p.digest,
      pr,
      keyLength = kl,
      valueLengthOpt = Some(vl))
    assert(vr.performOneOperation(l1).get.isDefined)
    assert(vr.performOneOperation(l2).get.isDefined)
    assert(vr.performOneOperation(l3).get.isEmpty)

    val i4 = Insert(key4, v1)
    val i5 = Insert(key5, v2)

    p.performOneOperation(i4)
    p.performOneOperation(i5)
    p.generateProof()

    val l4 = Lookup(key4)
    val l5 = Lookup(key5)
    val l6 = Lookup(key6)
    val l7 = Lookup(key7)

    val pr2 = {
      Seq(l1, l2, l3, l4, l5, l6).foreach(l => p.performOneOperation(l))
      p.generateProof()
    }

    val vr2 = new BatchAVLVerifier[D, HF](p.digest,
      pr2,
      keyLength = kl,
      valueLengthOpt = Some(vl))

    val pl2 = Seq(l1, l2, l3, l4, l5, l6).map(lookup =>
      lookup.key -> vr2.performOneOperation(lookup).get)
    println(pl2)
  }

  def smallDeleteTest = {
    def intToKey(k: Int): ADKey = {
      val key = new Array[Byte](32)
      key(0) = k.toByte
      ADKey @@ key
    }

    val value = randomValue(8)
    var newProver = new BatchAVLProver[D, HF](KL, Some(VL))

    def ins(k: Int) = {
      var m = Insert(intToKey(k), value)
      newProver.performOneOperation(m)
      print("Inserted ")
      println(k)
      newProver.checkTree()
      println(newProver)
    }

    def del(k: Int) = {
      var m = Remove(intToKey(k))
      newProver.performOneOperation(m)
      print("Removed ")
      println(k)
      newProver.checkTree()
      println(newProver)
    }

    deleteTest2

    def deleteTest2 = {
      def makeUnBalanced24EltTree = {
        newProver = new BatchAVLProver[D, HF](KL, Some(VL))
        ins(64)

        ins(32)
        ins(96)

        ins(16)
        ins(48)
        ins(80)
        ins(112)

        ins(8)
        ins(24)
        ins(40)
        ins(56)
        ins(72)
        ins(88)
        ins(104)
        ins(120)

        ins(68)
        ins(76)
        ins(84)
        ins(92)
        ins(100)
        ins(108)
        ins(116)
        ins(124)
      }

      makeUnBalanced24EltTree
      del(8)
      del(24)
      del(16)

      makeUnBalanced24EltTree
      del(40)
      del(56)
      del(48)

      makeUnBalanced24EltTree
      del(40)
      del(8)
      del(24)
      del(16)

      makeUnBalanced24EltTree
      del(56)
      del(8)
      del(24)
      del(16)

      makeUnBalanced24EltTree
      del(8)
      del(40)
      del(56)
      del(48)

      makeUnBalanced24EltTree
      del(24)
      del(40)
      del(56)
      del(48)
    }

    def deleteTest1 = {

      // testCase: 1 for testing deletes of the root, 2 for testing deletes to the left of the root, 3 for testing deletes to the right of the root

      val testCase = 3

      def clearTree = {
        newProver = new BatchAVLProver[D, HF](KL, Some(VL))
        if (testCase == 2) {
          ins(60)
          ins(70)
        }
        if (testCase == 3) {
          ins(3)
          ins(2)
        }
      }

      clearTree

      ins(20)

      // testCase *.a no children of the node being removed exist
      del(20)

      // testCase *.b: only left child of the node being removed exists
      clearTree

      ins(20)
      ins(10)
      del(20)

      // testCase *.c only right child of the node being removed exists
      clearTree

      ins(10)
      ins(20)
      del(10)

      // testCase *.d both children of the node being removed exist
      ins(10)
      ins(30)
      del(20)

      // testCase *.d.i both children of the node being removed exist, but right is deeper
      ins(8)
      ins(25)
      ins(35)
      del(10)

      // clear the tree because balance is all messed up now
      clearTree

      // testCase *.d.ii both children of the node being removed exist and are both deep
      ins(8)
      ins(5)
      ins(30)
      if (testCase == 2)
        ins(65)
      if (testCase == 3)
        ins(1)
      ins(7)
      ins(4)
      ins(25)
      ins(35)
      del(8)

      // testCase *.d.iii both children of the node being removed exist but left is deeper
      del(30)
      del(35)
      ins(6)
      del(7)
    }

  }

  def memoryTestWithBatching() = {
    // Generate a key out of an int
    def generateKey(i: Int, key: Array[Byte]) = {
      val r = i
      for (j <- 0 until 32)
        key(j) = ((r >> ((j % 4) * 8)) % 256).toByte
    }

    val newProver = new BatchAVLProver[D, HF](KL, Some(VL))
    val numKeys = 400000
    var p: Option[Seq[Byte]] = None
    var prevMemory: Long = Runtime.getRuntime().totalMemory() - Runtime
      .getRuntime()
      .freeMemory()
    var curMemory: Long = prevMemory

    for (i <- 1 until numKeys) {
      val key = ADKey @@ new Array[Byte](32)
      generateKey(i, key)
      val mod = Insert(key, randomValue(8))
      newProver.performOneOperation(mod)
    }
    newProver.digest
    newProver.generateProof()
    System.gc
    curMemory = Runtime.getRuntime().totalMemory() - Runtime
      .getRuntime()
      .freeMemory()
    println(curMemory)

    var i = 0
    var j = 0
    val key2 = ADKey @@ new Array[Byte](32)
    while (true) {
      i += 1
      var increment: Int = Random.randomBytes(1)(0).toInt
      if (increment < 0) increment = -increment
      j = (j + increment) % numKeys
      while (j <= 0) {
        increment = Random.randomBytes(1)(0)
        if (increment < 0) increment = -increment
        j = (j + increment) % numKeys
      }
      generateKey(j, key2)
      val mod = Update(key2, randomValue(8))
      newProver.performOneOperation(mod)
      if (i % 2000 == 0) {
        newProver.generateProof()
        newProver.digest
      }
      if (i % 50000 == 0) {
        System.gc
        prevMemory = curMemory
        curMemory = Runtime.getRuntime().totalMemory() - Runtime
          .getRuntime()
          .freeMemory()
        print(i)
        print(",")
        print(curMemory)
        print(",")
        println(curMemory - prevMemory)
      }
    }
  }

  /*
        if (i%2000 == 0) {
          print(i)
          print(",")
          newProver.digest

          prevMemory = curMemory
          //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
          print(curMemory)
          print(",")
          print(curMemory-prevMemory)
          print(",")

          p = Option(newProver.generateProof)
          prevMemory = curMemory
          //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
          print(curMemory-prevMemory)
          print(",")

          //System.gc
          prevMemory = curMemory
          //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
          print(curMemory-prevMemory)
          print(",")

          p = None
          System.gc
          prevMemory = curMemory
          //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
          println(curMemory-prevMemory)
        }
      }
    }
   */

  def memoryTestNoBatching() = {
    val oldProver = new AVLTree(32)
    val numMods = 1024 * 1024
    var p: Option[scala.util.Try[AVLModifyProof]] = None
    var prevMemory: Long = Runtime.getRuntime().totalMemory() - Runtime
      .getRuntime()
      .freeMemory()
    var curMemory: Long = prevMemory

    var i = 0
    while (true) {
      i += 1
      val mod = Insert(randomKey(), randomValue(8))
      p = Option(oldProver.run(mod))

      if (i % 2000 == 0) {
        print(i)
        print(",")
        oldProver.rootHash()

        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        print(curMemory)
        print(",")
        print(curMemory - prevMemory)
        print(",")

        //System.gc
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        print(curMemory - prevMemory)
        print(",")

        p = None
        System.gc()
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        println(curMemory - prevMemory)
      }
    }
  }

  def timeBenchmarksNew() = {
    val newProver = new BatchAVLProver[D, HF](KL, Some(VL))
    val numMods = 1024 * 1024

    val mod = new Array[Operation](1)
    for (i <- 0 until numMods) {
      mod(0) = Insert(randomKey(), randomValue(8))
      mod foreach (m => newProver.performOneOperation(m))
      if (i % 100000 == 0)
        println(i)
    }
    newProver.digest // NOTE: if you comment out this line, the first batch becomes about 2 seconds slower
    newProver.generateProof()

    val mods = new Array[Operation](75000)
    for (i <- 0 until 75000)
      mods(i) = Insert(randomKey(), randomValue(8))

    var i = 0
    for (k <- 0 until 10) {
      //NOTE: if you comment out this loop, the first few batches are slower by factor of 3-6
      val (newProverTime, pf) = time {
        var ctr = 0
        while (ctr < 1000) {
          for (j <- 0 until 1) {
            newProver.performOneOperation(mods(i))
            i += 1
            ctr += 1
          }
          newProver.digest
          newProver.generateProof()
        }
      }
      println(newProverTime)
    }

    var batchSize = 4096
    while (batchSize > 0) {
      var numBatches = 0
      val (newProverTime, pf) = time {
        var ctr = 0
        while (ctr < 4096) {
          for (j <- 0 until batchSize) {
            newProver.performOneOperation(mods(i))
            i += 1
            ctr += 1
          }
          newProver.digest
          newProver.generateProof()
          numBatches += 1
        }
      }
      print("batchSize = ")
      print(batchSize)
      print("; numBatches = ")
      print(numBatches)
      print("; newProverTime = ")
      print(newProverTime)
      print("; perInsert = ")
      println(newProverTime / numBatches / batchSize)
      batchSize /= 2
    }
  }

  def timeBenchmarksOld() = {
    val oldProver = new AVLTree(32)
    val numMods = 1024 * 1024

    val mod = new Array[Operation](1)
    for (i <- 0 until numMods) {
      mod(0) = Insert(randomKey(), randomValue(8))
      mod foreach (m => oldProver.run(m))
      if (i % 100000 == 0)
        println(i)
    }
    oldProver.rootHash()

    val mods = new Array[Operation](75000)
    for (i <- 0 until 75000)
      mods(i) = Insert(randomKey(), randomValue(8))

    var i = 0
    for (k <- 0 until 10) {
      val (oldProverTime, pf) = time {
        var ctr = 0
        while (ctr < 1000) {
          for (j <- 0 until 1) {
            oldProver.run(mods(i))
            i += 1
            ctr += 1
          }
          oldProver.rootHash()
        }
      }
      println(oldProverTime)
    }

    var batchSize = 4096
    while (batchSize > 0) {
      var numBatches = 0
      val (oldProverTime, pf) = time {
        var ctr = 0
        while (ctr < 4096) {
          for (j <- 0 until batchSize) {
            oldProver.run(mods(i))
            i += 1
            ctr += 1
          }
          oldProver.rootHash()
          numBatches += 1
        }
      }
      print("batchSize = ")
      print(batchSize)
      print("; numBatches = ")
      print(numBatches)
      print("; oldProverTime = ")
      print(oldProverTime)
      print("; perInsert = ")
      println(oldProverTime / numBatches / batchSize)
      batchSize /= 2
    }
  }

  def spaceBenchmarks() = {
    val newProver = new BatchAVLProver[D, HF](KL, Some(VL))

    val numMods = 1024 * 1024

    val mod = new Array[Operation](1)
    for (i <- 0 until numMods) {
      mod(0) = Insert(randomKey(), randomValue(8))
      mod foreach (m => newProver.performOneOperation(m))
      if (i % 10000 == 0)
        println(i)
    }
    val pf = newProver.generateProof()
    println(pf.length)

    var j = 1
    while (j < 2000000) {
      for (i <- 0 until j) {
        mod(0) = Insert(randomKey(), randomValue(8))
        mod foreach (m => newProver.performOneOperation(m))
      }
      print("j = ")
      println(j)
      val pf = newProver.generateProof()
      print("proof length ")
      println(pf.length)
      print("proof length per mod ")
      println(pf.length / j)
      j = j * 2
    }
  }

  def deleteProofSizeTest = {
    val newProver = new BatchAVLProver[D, HF](KL, Some(VL))
    val numMods = 1000000
    val testAtTheEnd = 2000

    // SEE COMMENT IN BIG DELETE TEST ON WHY THIS IS A BAD DATA STRUCTURE TO USE HERE
    val keys = new scala.collection.mutable.ListBuffer[ADKey]

    for (i <- 0 until numMods) {
      val key = randomKey()
      keys += key
      val m = Insert(key, randomValue(8))
      newProver.performOneOperation(m)
      if (i % 50000 == 0) println(i)
    }

    newProver.generateProof()

    var len = 0
    for (i <- 0 until testAtTheEnd) {
      val key = randomKey()
      keys += key
      val m = Insert(ADKey @@@ key, randomValue(8))
      newProver.performOneOperation(m)
      len += newProver.generateProof().length
    }
    //    len = newProver.generateProof().length
    println(len.toFloat / testAtTheEnd)

    len = 0
    for (i <- 0 until testAtTheEnd) {
      val j = Random.randomBytes(3)
      val key = ADKey @@@ keys(
        (j(0).toInt.abs + j(1).toInt.abs * 128 + j(2).toInt.abs * 128 * 128) % keys.size)
      keys -= key
      val m = Remove(key)
      newProver.performOneOperation(m)
      len += newProver.generateProof().length
    }
    //    len = newProver.generateProof().length
    println(len.toFloat / testAtTheEnd)

  }

  def batchingSelfTest = {
    def testZeroModProofOnEmptyTree = {
      val p = new BatchAVLProver[D, HF](KL, Some(VL))
      p.checkTree()
      val digest = p.digest
      val pf = p.generateProof()
      p.checkTree(true)
      val v =
        new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(0), Some(0))
      v.digest match {
        case None =>
          throw new Error("zero-mods verification failed to construct tree")
        case Some(d) =>
          require(d sameElements digest, "wrong digest for zero-mods")
      }
    }

    def testVariousVerifierFails = {
      val p = new BatchAVLProver[D, HF](KL, Some(VL))

      p.checkTree()
      for (i <- 0 until 1000) {
        require(
          p.performOneOperation(Insert(randomKey(), randomValue(8))).isSuccess,
          "failed to insert")
        p.checkTree()
      }
      p.generateProof()

      var digest = p.digest
      for (i <- 0 until 50)
        require(
          p.performOneOperation(Insert(randomKey(), randomValue(8))).isSuccess,
          "failed to insert")

      var pf = p.generateProof()
      // see if the proof for 50 mods will be allowed when we permit only 2
      var v =
        new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(2), Some(0))
      require(v.digest.isEmpty, "Failed to reject too long a proof")

      // see if wrong digest will be allowed
      v = new BatchAVLVerifier[D, HF](ADDigest @@ Random.randomBytes(),
        pf,
        KL,
        Some(VL),
        Some(50),
        Some(0))
      require(v.digest.isEmpty, "Failed to reject wrong digest")

      for (i <- 0 until 10) {
        digest = p.digest
        for (i <- 0 until 8)
          require(p.performOneOperation(Insert(randomKey(), randomValue(8)))
            .isSuccess,
            "failed to insert")

        v = new BatchAVLVerifier[D, HF](digest,
          p.generateProof(),
          KL,
          Some(VL),
          Some(8),
          Some(0))
        require(v.digest.nonEmpty, "verification failed to construct tree")
        // Try 5 inserts that do not match -- with overwhelming probability one of them will go to a leaf
        // that is not in the conveyed tree, and verifier will complain
        for (i <- 0 until 5)
          v.performOneOperation(Insert(randomKey(), randomValue(8)))
        require(
          v.digest.isEmpty,
          "verification succeeded when it should have failed, because of a missing leaf")

        digest = p.digest
        val key = randomKey()
        p.performOneOperation(Insert(ADKey @@@ key, randomValue(8)))
        pf = p.generateProof()
        p.checkTree()

        // Change the direction of the proof and make sure verifier fails
        pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
        v = new BatchAVLVerifier[D, HF](digest,
          pf,
          KL,
          Some(VL),
          Some(1),
          Some(0))
        require(v.digest.nonEmpty, "verification failed to construct tree")
        v.performOneOperation(Insert(key, randomValue(8)))
        require(
          v.digest.isEmpty,
          "verification succeeded when it should have failed, because of the wrong direction")

        // Change the key by a large amount -- verification should fail with overwhelming probability
        // because there are 1000 keys in the tree
        // First, change the proof back to be correct
        pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
        val oldKey = key(0)
        key(0) = (key(0) ^ (1 << 7)).toByte
        v = new BatchAVLVerifier[D, HF](digest,
          pf,
          KL,
          Some(VL),
          Some(1),
          Some(0))
        require(v.digest.nonEmpty, "verification failed to construct tree")
        v.performOneOperation(Insert(key, randomValue(8)))
        require(
          v.digest.isEmpty,
          "verification succeeded when it should have failed because of the wrong key")
        // put the key back the way it should be, because otherwise it's messed up in the prover tree
        key(0) = (key(0) ^ (1 << 7)).toByte

      }
    }

    def testSuccessfulChanges(toPrint: Boolean) = {
      def randomInt(max: Int) = scala.util.Random.nextInt(max)

      val p = new BatchAVLProver[D, HF](KL, Some(VL))

      val numMods = 5000

      val deletedKeys = new scala.collection.mutable.ArrayBuffer[ADKey]

      // Here we need a data structure that supports fast
      // random access by index; insert, delete, and modify (by index or by value -- we can work with either)
      // Something like a rank tree. I couldn't find anything standard in scala collections,
      // so I am using ArrayBuffer, which is terrible, because delete is slow.
      // ListBuffer would also be terrible here, because it doesn't have
      // fast lookup and remove by index
      // SetTree doesn't allow lookup by rank.
      val keysAndVals =
      new scala.collection.mutable.ArrayBuffer[(ADKey, ADValue)]

      var i = 0
      var numInserts = 0
      var numModifies = 0
      var numDeletes = 0
      var numNonDeletes = 0
      var numFailures = 0

      val t0 = System.nanoTime()
      while (i < numMods) {
        val digest = p.digest
        val n = randomInt(100)
        val j = i + n
        if (toPrint) {
          print("Now making ")
          print(n)
          print(" modifications; total until now ")
          print(i)
          print(". ")
        }
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
              require(
                p.performOneOperation(Insert(key, randomValue(8))).isFailure,
                "prover succeeded on inserting a value that's already in tree")
              p.checkTree()
              require(
                p.unauthenticatedLookup(key).get == keysAndVals(index)._2,
                "value changed after duplicate insert") // check insert didn't do damage
              numFailures += 1
            } else {
              val key = randomKey()
              val newVal = randomValue(8)
              keysAndVals += ((key, newVal))
              val mod = Insert(key, newVal)
              currentMods += mod
              require(p.performOneOperation(mod).isSuccess,
                "prover failed to insert")
              p.checkTree()
              require(p.unauthenticatedLookup(key).get == newVal,
                "inserted key is missing") // check insert
              numInserts += 1
            }
          } else {
            // with probability .25 update, with .25 delete
            if (randomInt(2) == 0) {
              // update
              if (randomInt(10) == 0) {
                // with probability 1/10 cause a fail by modifying a nonexisting key
                val key = randomKey()
                require(
                  p.performOneOperation(Update(key, randomValue(8))).isFailure,
                  "prover updated a nonexistent value")
                p.checkTree()
                require(
                  p.unauthenticatedLookup(key).isEmpty,
                  "a nonexistent value appeared after an update") // check update didn't do damage
                numFailures += 1
              } else {
                val index = randomInt(keysAndVals.size)
                val key = keysAndVals(index)._1
                val newVal = randomValue(8)
                val mod = Update(key, newVal)
                currentMods += mod
                require(p.performOneOperation(mod).isSuccess,
                  "prover failed to update value")
                keysAndVals(index) = key -> newVal
                require(p.unauthenticatedLookup(key).get.sameElements(newVal),
                  "wrong value after update") // check update
                numModifies += 1
              }
            } else {
              // delete
              if (randomInt(10) == 0) {
                // with probability 1/10 remove a nonexisting one but without failure -- shouldn't change the tree
                val key = randomKey()
                val mod = RemoveIfExists(key)
                val d = p.digest
                currentMods += mod
                require(p.performOneOperation(mod).isSuccess,
                  "prover failed when it should have done nothing")
                require(d sameElements p.digest,
                  "Tree changed when it shouldn't have")
                p.checkTree()
                numNonDeletes += 1
              } else {
                // remove an existing key
                val index = randomInt(keysAndVals.size)
                val key = keysAndVals(index)._1
                val mod = Remove(key)
                val oldVal = keysAndVals(index)._2
                currentMods += mod
                require(p.performOneOperation(mod).isSuccess,
                  "failed ot delete")
                keysAndVals -= ((key, oldVal))
                deletedKeys += key
                require(p.unauthenticatedLookup(key).isEmpty,
                  "deleted key still in tree") // check delete
                numDeletes += 1
                numCurrentDeletes += 1
              }
            }
          }
          i += 1
        }

        val pf = p.generateProof()
        p.checkTree(true)

        if (toPrint) {
          print("Average Proof Length ")
          print(pf.length.toFloat / n)
          if (i > 0) {
            print("; time so far = ")
            println((System.nanoTime() - t0) / i)
          }
        }

        val v = new BatchAVLVerifier[D, HF](digest,
          pf,
          KL,
          Some(VL),
          Some(n),
          Some(numCurrentDeletes))
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
            require(d sameElements p.digest,
              "Tree has wrong digest after verification")
        }
      }

      // Check that all the inserts, deletes, and updates we did actually stayed
      deletedKeys foreach (k =>
        require(p.unauthenticatedLookup(k).isEmpty,
          "Key that was deleted is still in the tree"))
      keysAndVals foreach (pair =>
        require(p.unauthenticatedLookup(pair._1).get == pair._2,
          "Key has wrong value"))

      if (toPrint) {
        print("NumInserts = ")
        println(numInserts)
        print("NumDeletes = ")
        println(numDeletes)
        print("NumNonDeletes = ")
        println(numNonDeletes)
        print("NumModifies = ")
        println(numModifies)
        print("NumFailures = ")
        println(numFailures)
      }
    }

    testZeroModProofOnEmptyTree
    testVariousVerifierFails
    testSuccessfulChanges(true)
  }

  case class ModifyingLookup(override val key: ADKey) extends Modification {
    override def updateFn: UpdateFunction = old => Success(old)
  }

  def testReadme() = {
    val prover =
      new BatchAVLProver[D, HF](keyLength = 1, valueLengthOpt = Some(VL))
    val initialDigest = prover.digest
    val key1 = ADKey @@ Array(1: Byte)
    val key2 = ADKey @@ Array(2: Byte)
    val key3 = ADKey @@ Array(3: Byte)
    val op1 = Insert(key1, ADValue @@ Longs.toByteArray(10L))
    val op2 = Insert(key2, ADValue @@ Longs.toByteArray(20L))
    val op3 = Insert(key3, ADValue @@ Longs.toByteArray(30L))
    require(prover.performOneOperation(op1).get.isEmpty) // Should return None
    require(prover.performOneOperation(op2).get.isEmpty) // Should return None
    require(prover.performOneOperation(op3).get.isEmpty) // Should return None
    val proof1 = prover.generateProof()
    val digest1 = prover.digest

    val op4 = Update(key1, ADValue @@ Longs.toByteArray(50L))
    val op5 = UpdateLongBy(key2, -40)
    val op6 = Lookup(key3)
    val op7 = Remove(ADKey @@ Array(5: Byte))
    val op8 = Remove(key3)
    require(
      prover.performOneOperation(op4).get.get sameElements Longs.toByteArray(
        10))
    require(
      prover.unauthenticatedLookup(key1).get sameElements Longs.toByteArray(50))
    require(!prover.performOneOperation(op5).isSuccess) // Fails
    require(
      prover.performOneOperation(op6).get.get sameElements Longs.toByteArray(
        30))
    require(!prover.performOneOperation(op7).isSuccess) // Fails
    require(
      prover.performOneOperation(op8).get.get sameElements Longs.toByteArray(
        30))
    val proof2 = prover.generateProof() // Proof onlyu for op4 and op6
    val digest2 = prover.digest

    val verifier1 = new BatchAVLVerifier[D, HF](initialDigest,
      proof1,
      keyLength = 1,
      valueLengthOpt = Some(VL),
      maxNumOperations = Some(2),
      maxDeletes = Some(0))
    require(verifier1.performOneOperation(op1).get.isEmpty) // Should return None
    require(verifier1.performOneOperation(op2).get.isEmpty) // Should return None
    require(verifier1.performOneOperation(op3).get.isEmpty) // Should return None
    verifier1.digest match {
      case Some(d1) if digest1.sameElements(digest1) =>
        //If digest1 from the prover is already trusted, then verification of the second batch can simply start here
        val verifier2 = new BatchAVLVerifier[D, HF](d1,
          proof2,
          keyLength = 1,
          valueLengthOpt = Some(VL),
          maxNumOperations = Some(3),
          maxDeletes = Some(1))
        require(
          verifier2.performOneOperation(op4).get.get sameElements Longs
            .toByteArray(10))
        require(
          verifier2.performOneOperation(op6).get.get sameElements Longs
            .toByteArray(30))
        require(
          verifier2.performOneOperation(op8).get.get sameElements Longs
            .toByteArray(30))
        verifier2.digest match {
          case Some(d2) if d2.sameElements(digest2) =>
            println("declared root2 value and proofs are valid")
          case _ => println("second proof or announced root value NOT valid")
        }
      case _ =>
        println("first proof or announced root1 NOT valid")
    }
  }
}
