package scorex.crypto.authds.benchmarks

import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch._
import scorex.crypto.authds.avltree.legacy.{AVLModifyProof, AVLTree}
import scorex.utils.Random
import scorex.crypto.authds.avltree._
import scala.util.Success

/**
  * TODO: describe benchmark
  */
object BatchingBenchmark extends App with TwoPartyTests {

  println ("treeSize, numLookups, proofSizeForEach")
  benchSizeLookupsInTree(1000000, Seq(1000), false, false)
  benchSizeLookupsInTree(1000000, Seq(1000), true, false)
  benchSizeLookupsInTree(1000000, Seq(1000), false, true)
  benchSizeLookupsInTree(1000000, Seq(1000), true, true)

  bench2()
//  timeBenchmarksNewContinuous
//  timeBenchmarksOldContinuous
//  timeBenchmarksNew
//  timeBenchmarksOld



  def bench2(): Unit = {

    val InitialMods = 1000000
    val NumMods = InitialMods + 4096 * 64
    var digest = Array[Byte]()

    val mods = generateModifications(NumMods)

    println("Step, Plain size, GZiped size, Batched size, Old apply time, New apply time, Old verify time, New verify time")

    val steps = Seq(64, 32, 16, 8, 4, 2, 1)


    //    val steps = Seq(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 4096 * 2, 4096 * 4, 4096 * 8, 4096 * 16,
    //     4096 * 32, 4096 * 64)

    steps foreach { j =>
      val oldProver = new LegacyProver(new AVLTree(32))
      val newProver = new BatchAVLProver()

      val Step = InitialMods / 1000
      (0 until(InitialMods, Step)) foreach { cur =>
        val initialModifications = Modification.convert(mods.slice(cur, cur + Step))
        oldProver.applyUpdates(initialModifications)
        initialModifications foreach (m => newProver.performOneModification(m._1, m._2))
        newProver.generateProof
        digest = newProver.rootHash
        require(oldProver.rootHash sameElements digest)
      }

      oneStep(InitialMods, j, j, 1024*32,oldProver, newProver, mods)
    }
  }

  def bench1(): Unit = {
    val InitialMods = 1000000
    val NumMods = InitialMods + 4096 * 64
    var digest = Array[Byte]()

    val mods = generateModifications(NumMods)

    println("Step, Plain size, GZiped size, Batched size, Old apply time, New apply time, Old verify time, New verify time")

    val oldProver = new LegacyProver(new AVLTree(32))
    val newProver = new BatchAVLProver()

    val initialModifications = Modification.convert(mods.slice(0, InitialMods))
    oldProver.applyUpdates(initialModifications)
    initialModifications foreach (m => newProver.performOneModification(m._1, m._2))
    newProver.generateProof
    digest = newProver.rootHash
    require(oldProver.rootHash sameElements digest)

    val Step = 1000
    (InitialMods until(NumMods, Step)) foreach { i =>
      oneStep(i, Step, i, i, oldProver, newProver, mods)
    }
  }

  def oneStep(i: Int, step: Int, toPrint: Int, totalSize: Int, oldProver: LegacyProver, newProver: BatchAVLProver[_], mods: Array[Modification]): Unit = {
    System.gc()

    var oldProverTime = 0.0
    var newProverTime = 0.0
    var oldVerifierTime = 0.0
    var newVerifierTime = 0.0
    var oldSize = 0.0
    var newSize = 0.0
    var gzippedSize = 0.0

    for (iteration <- 0 until (totalSize, step)) {

      val converted = Modification.convert(mods.slice(i+iteration, i + iteration + step))
      var digest = oldProver.rootHash


      val (oldProverTimeT, oldProofs: Seq[AVLModifyProof]) = time {
        oldProver.applyUpdates(converted) match {
          case a: BatchSuccessSimple =>
            oldProver.rootHash
            // TODO: THIS IS NOT THE MOST EFFICIENCT SERIALIZATION,
            // SO IT'S A BIT UNFAIR TO OLDPROVER
            a.proofs foreach (p=>p.bytes)
            a.proofs
          case BatchFailure(e) => throw e
        }
      }

      oldProverTime+=oldProverTimeT

      val oldBytes = oldProofs.foldLeft(Array[Byte]()) { (a, b) =>
        a ++ b.proofSeq.map(_.bytes).reduce(_ ++ _)
      }

      // TODO: THERE IS NO DESERIALIZATION
      // SO IT'S A BIT TOO NICE TO OLDVERIFIER
      val oldVerifierTimeT = time {
        var h = 0
        oldProofs.foldLeft(digest) { (prevDigest, proof) =>
          val newDigest = proof.verify(prevDigest, converted(h)._2).get
          h = h + 1
          newDigest
        }
      }._1

      oldVerifierTime+=oldVerifierTimeT

      oldSize = oldBytes.length.toFloat / step
      gzippedSize = Gzip.compress(oldBytes).length.toFloat / step

      newProver.rootHash
      val (newProverTimeT, pf) = time {
        converted foreach (m => newProver.performOneModification(m._1, m._2))
        newProver.rootHash
        newProver.generateProof.toArray
      }
      newProverTime+=newProverTimeT
      newSize = pf.length.toFloat / step

      val (newVerifierTimeT, _) = time {
        val newVerifier = new BatchAVLVerifier(digest, pf)
        converted foreach (m => newVerifier.performOneModification(m._1, m._2))
        newVerifier.digest
      }
      newVerifierTime += newVerifierTimeT

    }
    println(s"$toPrint,$oldSize,$gzippedSize,$newSize,${oldProverTime / totalSize},${newProverTime / totalSize}," +
      s"${oldVerifierTime / totalSize},${newVerifierTime / totalSize}")
  }

  def timeBenchmarksNewProverInsertOnly {
    val newProver = new BatchAVLProver()
    val numMods = 1024*1024
    val batchSize = 1

    var mods = new Array[Modification](1024)
    for (i <- 0 until 1024) {
      for (j <- 0 until 1024)
        mods(j) = Insert(Random.randomBytes(), Random.randomBytes(8))
      val converted = Modification.convert(mods)
      val (t, d) = time {
        var j=0
        while (j<1024) {
          for (k <- 0 until batchSize)
            newProver.performOneModification(converted(j+k)._1, converted(j+k)._2)
          newProver.generateProof.toArray
          newProver.rootHash
          j+=batchSize
        }
      }
      print(i)
      print(" ")
      println(t)
    }
  }

  def timeBenchmarksOldProverInsertOnly {
    val oldProver = new AVLTree(32)
    val numMods = 1024*1024
    val batchSize = 1024

    var mods = new Array[Modification](1024)
    for (i <- 0 until 1024) {
      for (j <- 0 until 1024)
        mods(j) = Insert(Random.randomBytes(), Random.randomBytes(8))
      val converted = Modification.convert(mods)
      val (t, d) = time {
        var j=0
        while (j<1024) {
          for (k <- 0 until batchSize)
            oldProver.modify(converted(j+k)._1, converted(j+k)._2).get.bytes
          oldProver.rootHash()
          j+=batchSize
        }
      }
      print(i)
      print(" ")
      println(t)
    }
  }


  def timeBenchmarkNewProver {
    val initialMods = 1024*1024
    val totalSize = 32*1024
    val measuredMods = 32*1024*20
    val mods = generateModifications(initialMods+measuredMods)

    /*  for (k<-0 until 10) { //NOTE: if you comment out this loop, the first few batches are slower by factor of 3-6
        val (newProverTime, pf) = time {
          var ctr = 0
          while(ctr<1000) {
            for (j<-0 until 1) {
              val m = Modification.convert(mods(i))
              newProver.performOneModification(m._1, m._2)
              i+=1
              ctr+=1
            }
            newProver.rootHash
            newProver.generateProof.toArray
          }
        }
        println(newProverTime)
      }*/

    println("batchSize,UnitCost")
    var batchSize = totalSize
    while (batchSize > 0) {

      val newProver = new BatchAVLProver()
      for (i<-0 until initialMods) {
        val m = Modification.convert(mods(i))
        newProver.performOneModification(m._1, m._2)
      }
      newProver.rootHash // NOTE: if you comment out this line, the first batch becomes about 2 seconds slower
      newProver.generateProof

      System.gc()

      var i = initialMods

      var numBatches = 0
      val (newProverTime, pf) = time {
        var ctr = 0
        while(ctr<totalSize) {
          for (j<-0 until batchSize) {
            val m = Modification.convert(mods(i))
            newProver.performOneModification(m._1, m._2)
            i+=1
            ctr+=1
          }
          newProver.rootHash
          newProver.generateProof.toArray
          numBatches += 1
        }
      }
      print(batchSize)
      print(",")
      println(newProverTime/numBatches/batchSize)
      batchSize/=2
    }
  }

  def timeBenchmarkOldProver {
    val initialMods = 1024*1024
    val totalSize = 32*1024
    val measuredMods = 32*1024*20
    val mods = generateModifications(initialMods+measuredMods)



    /*  for (k<-0 until 10) { //NOTE: if you comment out this loop, the first few batches are slower by factor of 3-6
        val (oldProverTime, pf) = time {
          var ctr = 0
          while(ctr<1000) {
            for (j<-0 until 1) {
              val m = Modification.convert(mods(i))
              oldProver.modify(m._1, m._2).get.bytes
              i+=1
              ctr+=1
            }
            oldProver.rootHash
          }
        }
        println(oldProverTime)
      }*/

    println("batchSize,UnitCost")
    var batchSize = totalSize
    while (batchSize > 0) {

      val oldProver = new AVLTree(32)
      for (i<-0 until initialMods) {
        val m = Modification.convert(mods(i))
        oldProver.modify(m._1, m._2)
      }
      oldProver.rootHash() // NOTE: if you comment out this line, the first batch becomes about 2 seconds slower

      System.gc()

      var i = initialMods

      var numBatches = 0
      val (oldProverTime, pf) = time {
        var ctr = 0
        while(ctr<totalSize) {
          for (j<-0 until batchSize) {
            val m = Modification.convert(mods(i))
            oldProver.modify(m._1, m._2).get.bytes
            i+=1
            ctr+=1
          }
          oldProver.rootHash()
          numBatches += 1
        }
      }
      print(batchSize)
      print(",")
      println(oldProverTime/numBatches/batchSize)
      batchSize/=2
    }
  }


  def benchSizeLookupsInTree(treeSize:Int, lookups: Seq[Int], useFreshLookups : Boolean, halfInserts: Boolean) = {
    val mods = new Array[(AVLKey, UpdateFunction)](treeSize)
    for (i<-0 until treeSize)
      mods(i) = Modification.convert(Insert(Random.randomBytes(), Random.randomBytes(8)))

    val newProver = new BatchAVLProver()
    mods.foreach (m => newProver.performOneModification(m._1, m._2))
    newProver.generateProof
    val digest = newProver.rootHash

    for (n <- lookups) {
      // perform n lookups for random values, or n/2 lookups/inserts
      for (i<-0 until n) {
        if (!halfInserts || i%2 == 0) {
          if (useFreshLookups) { // unsuccessful lookup
            newProver.performOneModification(Random.randomBytes(), (k=>Success(None)):UpdateFunction)
          } else { // successful lookup with a change
          val j = Random.randomBytes(3)
            val m = Update(mods((j(0).toInt.abs + j(1).toInt.abs * 128 + j(2).toInt.abs * 128 * 128) % treeSize)._1, Random.randomBytes(8))
            val c = Modification.convert(m)
            newProver.performOneModification(c._1, c._2)
          }
        } else { // new insert
        val m = Insert(Random.randomBytes(), Random.randomBytes(8))
          val c = Modification.convert(m)
          newProver.performOneModification(c._1, c._2)
        }
      }
      if (useFreshLookups && !halfInserts) assert (digest sameElements newProver.rootHash)
      print(treeSize)
      print(",")
      print(n)
      print(",")
      println(newProver.generateProof.length.toFloat/n)
    }
  }


  def generateModifications(NumMods : Int): Array[Modification] = {
    val mods = new Array[Modification](NumMods)
    mods(0) = Insert(Random.randomBytes(), Random.randomBytes(8))

    for (i <- 1 until NumMods) {
      if (i % 2 == 0) {
        // half inserts, half lookups
        mods(i) = Insert(Random.randomBytes(), Random.randomBytes(8))
      } else {
        val j = Random.randomBytes(3)
        mods(i) = Update(mods((j(0).toInt.abs + j(1).toInt.abs * 128 + j(2).toInt.abs * 128 * 128) % i).key, Random.randomBytes(8))
      }
    }
    mods
  }
}
