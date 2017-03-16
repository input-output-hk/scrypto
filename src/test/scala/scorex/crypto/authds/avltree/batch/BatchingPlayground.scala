package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.avltree._
import scorex.crypto.authds.legacy.avltree.AVLTree
import scorex.crypto.authds.legacy.avltree.{AVLModifyProof, AVLTree}
import scorex.utils.Random


object BatchingPlayground extends App {
  def time[R](block: => R): (Float, R) = {
    val t0 = System.nanoTime()
    val result = block // call-by-name
    val t1 = System.nanoTime()
    ((t1 - t0).toFloat / 1000000, result)
  }

  //smallDeleteTest
  batchingSelfTest

  //deleteProofSizeTest

  //memoryTestWithBatching
  //memoryTestNoBatching
  //timeBenchmarksNew
  //timeBenchmarksOld
  //spaceBenchmarks


  def smallDeleteTest = {
    def intToKey(k: Int): Array[Byte] = {
      val key = new Array[Byte](32)
      key(0) = k.toByte
      key
    }

    val value = Random.randomBytes(8)
    var newProver = new BatchAVLProver()

    def ins(k: Int) = {
      var m = Insert(intToKey(k), value)
      newProver.performOneModification(m)
      print("Inserted ")
      println(k)
      newProver.checkTree()
      println(newProver)
    }

    def del(k: Int) = {
      var m = Remove(intToKey(k))
      newProver.performOneModification(m)
      print("Removed ")
      println(k)
      newProver.checkTree()
      println(newProver)
    }


    deleteTest2

    def deleteTest2 = {
      def makeUnBalanced24EltTree = {
        newProver = new BatchAVLProver
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
        newProver = new BatchAVLProver()
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


  def memoryTestWithBatching {
    // Generate a key out of an int
    def generateKey(i: Int, key: Array[Byte]) {
      val r = i
      for (j <- 0 until 32)
        key(j) = ((r >> ((j % 4) * 8)) % 256).toByte
    }

    val newProver = new BatchAVLProver()
    val numKeys = 400000
    var p: Option[Seq[Byte]] = None
    var prevMemory: Long = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
    var curMemory: Long = prevMemory

    for (i <- 1 until numKeys) {
      val key = new Array[Byte](32)
      generateKey(i, key)
      val mod = Insert(key, Random.randomBytes(8))
      newProver.performOneModification(mod)
    }
    newProver.digest
    newProver.generateProof
    System.gc
    curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
    println(curMemory)

    var i = 0
    var j = 0
    val key2 = new Array[Byte](32)
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
      val mod = Update(key2, Random.randomBytes(8))
      newProver.performOneModification(mod)
      if (i % 2000 == 0) {
        newProver.generateProof
        newProver.digest
      }
      if (i % 50000 == 0) {
        System.gc
        prevMemory = curMemory
        curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
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

  def memoryTestNoBatching {
    val oldProver = new AVLTree(32)
    val numMods = 1024 * 1024
    var p: Option[scala.util.Try[AVLModifyProof]] = None
    var prevMemory: Long = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
    var curMemory: Long = prevMemory

    var i = 0
    while (true) {
      i += 1
      val mod = (Insert(Random.randomBytes(), Random.randomBytes(8)))
      p = Option(oldProver.modify(mod))

      if (i % 2000 == 0) {
        print(i)
        print(",")
        oldProver.rootHash

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
        System.gc
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        println(curMemory - prevMemory)
      }
    }
  }

  def timeBenchmarksNew {
    val newProver = new BatchAVLProver()
    val numMods = 1024 * 1024

    val mod = new Array[Operation](1)
    for (i <- 0 until numMods) {
      mod(0) = Insert(Random.randomBytes(), Random.randomBytes(8))
      mod foreach (m => newProver.performOneModification(m))
      if (i % 100000 == 0)
        println(i)
    }
    newProver.digest // NOTE: if you comment out this line, the first batch becomes about 2 seconds slower
    newProver.generateProof

    val mods = new Array[Operation](75000)
    for (i <- 0 until 75000)
      mods(i) = Insert(Random.randomBytes(), Random.randomBytes(8))

    var i = 0
    for (k <- 0 until 10) {
      //NOTE: if you comment out this loop, the first few batches are slower by factor of 3-6
      val (newProverTime, pf) = time {
        var ctr = 0
        while (ctr < 1000) {
          for (j <- 0 until 1) {
            newProver.performOneModification(mods(i))
            i += 1
            ctr += 1
          }
          newProver.digest
          newProver.generateProof.toArray
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
            newProver.performOneModification(mods(i))
            i += 1
            ctr += 1
          }
          newProver.digest
          newProver.generateProof.toArray
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


  def timeBenchmarksOld {
    val oldProver = new AVLTree(32)
    val numMods = 1024 * 1024

    val mod = new Array[Operation](1)
    for (i <- 0 until numMods) {
      mod(0) = (Insert(Random.randomBytes(), Random.randomBytes(8)))
      mod foreach (m => oldProver.modify(m))
      if (i % 100000 == 0)
        println(i)
    }
    oldProver.rootHash

    val mods = new Array[Operation](75000)
    for (i <- 0 until 75000)
      mods(i) = Insert(Random.randomBytes(), Random.randomBytes(8))

    var i = 0
    for (k <- 0 until 10) {
      val (oldProverTime, pf) = time {
        var ctr = 0
        while (ctr < 1000) {
          for (j <- 0 until 1) {
            oldProver.modify(mods(i))
            i += 1
            ctr += 1
          }
          oldProver.rootHash
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
            oldProver.modify(mods(i))
            i += 1
            ctr += 1
          }
          oldProver.rootHash
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


  def spaceBenchmarks {
    val newProver = new BatchAVLProver()

    val numMods = 1024 * 1024

    val mod = new Array[Operation](1)
    for (i <- 0 until numMods) {
      mod(0) = (Insert(Random.randomBytes(), Random.randomBytes(8)))
      mod foreach (m => newProver.performOneModification(m))
      if (i % 10000 == 0)
        println(i)
    }
    val pf = newProver.generateProof.toArray
    println(pf.length)

    var j = 1
    while (j < 2000000) {
      for (i <- 0 until j) {
        mod(0) = (Insert(Random.randomBytes(), Random.randomBytes(8)))
        mod foreach (m => newProver.performOneModification(m))
      }
      print("j = ")
      println(j)
      val pf = newProver.generateProof.toArray
      print("proof length ")
      println(pf.length)
      print("proof length per mod ")
      println(pf.length / j)
      j = j * 2
    }
  }

  def deleteProofSizeTest = {
    val newProver = new BatchAVLProver()
    val numMods = 1000000
    val testAtTheEnd = 2000

    // SEE COMMENT IN BIG DELETE TEST ON WHY THIS IS A BAD DATA STRUCTURE TO USE HERE
    val keys = new scala.collection.mutable.ListBuffer[AVLKey]

    for (i <- 0 until numMods) {
      val key = Random.randomBytes()
      keys += key
      val m = Insert(key, Random.randomBytes(8))
      newProver.performOneModification(m)
      if (i % 50000 == 0) println(i)
    }

    newProver.generateProof

    var len = 0
    for (i <- 0 until testAtTheEnd) {
      val key = Random.randomBytes()
      keys += key
      val m = Insert(key, Random.randomBytes(8))
      newProver.performOneModification(m)
      len += newProver.generateProof.toArray.length
    }
    //    len = newProver.generateProof.toArray.length
    println(len.toFloat / testAtTheEnd)

    len = 0
    for (i <- 0 until testAtTheEnd) {
      val j = Random.randomBytes(3)
      val key = keys((j(0).toInt.abs + j(1).toInt.abs * 128 + j(2).toInt.abs * 128 * 128) % keys.size)
      keys -= key
      val m = Remove(key)
      newProver.performOneModification(m)
      len += newProver.generateProof.toArray.length
    }
    //    len = newProver.generateProof.toArray.length
    println(len.toFloat / testAtTheEnd)

  }

  def batchingSelfTest = {
    def testZeroModProofOnEmptyTree = {
      val p = new BatchAVLProver()
      p.checkTree()
      val digest = p.digest
      val pf = p.generateProof.toArray
      p.checkTree(true)
      val v = new BatchAVLVerifier(digest, pf, 32, 8, Some(0), Some(0))
      v.digest match {
        case None =>
          require(false, "zero-mods verification failed to construct tree")
        case Some(d) =>
          require(d sameElements digest, "wrong digest for zero-mods")
      }
    }

    def testVariousVerifierFails = {
      val p = new BatchAVLProver()

      p.checkTree()
      for (i <- 0 until 1000) {
        require(p.performOneModification(Insert(Random.randomBytes(), Random.randomBytes(8))).isSuccess, "failed to insert")
        p.checkTree()
      }
      p.generateProof

      var digest = p.digest
      for (i <- 0 until 50)
        require(p.performOneModification(Insert(Random.randomBytes(), Random.randomBytes(8))).isSuccess, "failed to insert")

      var pf = p.generateProof.toArray
      // see if the proof for 50 mods will be allowed when we permit only 2
      var v = new BatchAVLVerifier(digest, pf, 32, 8, Some(2), Some(0))
      require(v.digest.isEmpty, "Failed to reject too long a proof")

      // see if wrong digest will be allowed
      v = new BatchAVLVerifier(Random.randomBytes(), pf, 32, 8, Some(50), Some(0))
      require(v.digest.isEmpty, "Failed to reject wrong digest")

      for (i <- 0 until 10) {
        digest = p.digest
        for (i <- 0 until 8)
          require(p.performOneModification(Insert(Random.randomBytes(), Random.randomBytes(8))).isSuccess, "failed to insert")

        v = new BatchAVLVerifier(digest, p.generateProof.toArray, 32, 8, Some(8), Some(0))
        require(v.digest.nonEmpty, "verification failed to construct tree")
        // Try 5 inserts that do not match -- with overwhelming probability one of them will go to a leaf
        // that is not in the conveyed tree, and verifier will complain
        for (i <- 0 until 5)
          v.performOneModification(Insert(Random.randomBytes(), Random.randomBytes(8)))
        require(v.digest.isEmpty, "verification succeeded when it should have failed, because of a missing leaf")

        digest = p.digest
        val key = Random.randomBytes()
        p.performOneModification(Insert(key, Random.randomBytes(8)))
        pf = p.generateProof.toArray
        p.checkTree()

        // Change the direction of the proof and make sure verifier fails
        pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
        v = new BatchAVLVerifier(digest, pf, 32, 8, Some(1), Some(0))
        require(v.digest.nonEmpty, "verification failed to construct tree")
        v.performOneModification(Insert(key, Random.randomBytes(8)))
        require(v.digest.isEmpty, "verification succeeded when it should have failed, because of the wrong direction")

        // Change the key by a large amount -- verification should fail with overwhelming probability
        // because there are 1000 keys in the tree
        // First, change the proof back to be correct
        pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
        val oldKey = key(0)
        key(0) = (key(0) ^ (1 << 7)).toByte
        v = new BatchAVLVerifier(digest, pf, 32, 8, Some(1), Some(0))
        require(v.digest.nonEmpty, "verification failed to construct tree")
        v.performOneModification(Insert(key, Random.randomBytes(8)))
        require(v.digest.isEmpty, "verification succeeded when it should have failed because of the wrong key")
        // put the key back the way it should be, because otherwise it's messed up in the prover tree
        key(0) = (key(0) ^ (1 << 7)).toByte

      }
    }



    def testSuccessfulChanges(toPrint: Boolean) = {
      def randomInt(max: Int) = scala.util.Random.nextInt(max)

      val p = new BatchAVLProver()

      val numMods = 5000

      val deletedKeys = new scala.collection.mutable.ArrayBuffer[AVLKey]

      // Here we need a data structure that supports fast
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
              require(p.performOneModification(Insert(key, Random.randomBytes(8))).isFailure, "prover succeeded on inserting a value that's already in tree")
              p.checkTree()
              require(p.unauthenticatedLookup(key).get == keysAndVals(index)._2, "value changed after duplicate insert") // check insert didn't do damage
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
              require(p.unauthenticatedLookup(key).get == newVal, "inserted key is missing") // check insert
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
                keysAndVals(index) = ((key, newVal))
                require(p.unauthenticatedLookup(key).get == newVal, "wrong value after update") // check update
                numModifies += 1
              }
            } else {
              // delete
              if (randomInt(10) == 0) {
                // with probability 1/10 remove a nonexisting one but without failure -- shouldn't change the tree
                val key = Random.randomBytes()
                val mod = RemoveIfExists(key)
                val d = p.digest
                currentMods += mod
                require(p.performOneModification(mod).isSuccess, "prover failed when it should have done nothing")
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
                require(p.performOneModification(mod).isSuccess, "failed ot delete")
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

        if (toPrint) {
          print("Average Proof Length ")
          print(pf.length.toFloat / n)
          if (i > 0) {
            print("; time so far = ")
            println((System.nanoTime() - t0) / i)
          }
        }

        val v = new BatchAVLVerifier(digest, pf, 32, 8, Some(n), Some(numCurrentDeletes))
        v.digest match {
          case None =>
            require(false, "Verification failed to construct the tree")
          case Some(d) =>
            require(d sameElements digest, "Built tree with wrong digest") // Tree built successfully
        }

        currentMods foreach (m => v.performOneModification(m))
        v.digest match {
          case None =>
            require(false, "Verification failed")
          case Some(d) =>
            require(d sameElements p.digest, "Tree has wrong digest after verification")
        }
      }

      // Check that all the inserts, deletes, and updates we did actually stayed 
      deletedKeys foreach (k => require(p.unauthenticatedLookup(k).isEmpty, "Key that was deleted is still in the tree"))
      keysAndVals foreach (pair => require(p.unauthenticatedLookup(pair._1).get == pair._2, "Key has wrong value"))

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
}

