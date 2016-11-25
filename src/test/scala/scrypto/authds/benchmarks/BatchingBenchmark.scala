package scrypto.authds.benchmarks

import scrypto.authds.TwoPartyTests
import scrypto.authds.avltree.batch._
import scrypto.authds.avltree.{AVLModifyProof, AVLTree}
import scrypto.utils.Random

object BatchingBenchmark extends App with TwoPartyTests {

    val InitilaMods = 1000000
    val NumMods = InitilaMods + 4096 * 64
//  val InitilaMods = 0
//  val NumMods = 2000000

  var digest = Array[Byte]()

  var numInserts = 0

  val mods = generateModifications()

  println(s"NumInserts = $numInserts")
  println("Step, Plain size, GZiped size, Batched size, Old apply time, New apply time, Old verify time, New verify time")

  bench2()

  def bench1(): Unit = {
    val oldProver = new oldProver(new AVLTree(32))
    val newProver = new BatchAVLProver()

    val initialModifications = Modification.convert(mods.slice(0, InitilaMods))
    oldProver.applyUpdates(initialModifications)
    initialModifications foreach (m => newProver.performOneModification(m._1, m._2))
    newProver.generateProof
    digest = newProver.rootHash
    require(oldProver.rootHash sameElements digest)

    val Step = 2000
    (InitilaMods until(NumMods, Step)) foreach { i =>
      oneStep(i, Step, i / 2, oldProver, newProver)
    }
  }


  def bench2(): Unit = {

    val steps = Seq(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 4096 * 2, 4096 * 4, 4096 * 8, 4096 * 16,
      4096 * 32, 4096 * 64)

    steps foreach { j =>
      val oldProver = new oldProver(new AVLTree(32))
      val newProver = new BatchAVLProver()

      val Step = InitilaMods / 1000
      (0 until(InitilaMods, Step)) foreach { cur =>
        val initialModifications = Modification.convert(mods.slice(cur, cur + Step))
        oldProver.applyUpdates(initialModifications)
        initialModifications foreach (m => newProver.performOneModification(m._1, m._2))
        newProver.generateProof
        digest = newProver.rootHash
        require(oldProver.rootHash sameElements digest)
      }

      oneStep(InitilaMods, j, j, oldProver, newProver)
    }
  }

  def oneStep(i: Int, step: Int, toPrint: Int, oldProver: oldProver, newProver: BatchAVLProver[_]): Unit = {
    System.gc()
    val converted = Modification.convert(mods.slice(i, i + step))

    val (oldProverTime, oldProves: Seq[AVLModifyProof]) = time {
      oldProver.applyUpdates(converted) match {
        case a: BatchSuccessSimple =>
          val proofs = a.proofs
          a.proofs.foreach(_.bytes)
          proofs
        case BatchFailure(e) => throw e
      }
    }
    val oldBytes = oldProves.foldLeft(Array[Byte]()) { (a, b) =>
      a ++ b.proofSeq.map(_.bytes).reduce(_ ++ _)
    }
    val oldVerifierTime: Float = time {
      var h = 0
      oldProves.foldLeft(digest) { (prevDigest, proof) =>
        val newDigest = proof.verify(prevDigest, converted(h)._2).get
        h = h + 1
        newDigest
      }
    }._1

    val oldSize = oldBytes.length.toFloat / step
    val gzippedSize = Gzip.compress(oldBytes).length.toFloat / step

    newProver.rootHash
    val (newProverTime, pf) = time {
      converted foreach (m => newProver.performOneModification(m._1, m._2))
      newProver.rootHash
      newProver.generateProof
    }
    val newSize = pf.length.toFloat / step

    val newVerifier = new BatchAVLVerifier(digest, pf.toArray)
    newVerifier.digest.get shouldEqual digest

    digest = oldProver.rootHash
    assert(newProver.rootHash sameElements digest)

    val (newVerifierTime, _) = time {
      converted foreach (m => newVerifier.verifyOneModification(m._1, m._2))
      newVerifier.digest
    }
    newVerifier.digest.get shouldEqual digest
    println(s"$toPrint,$oldSize,$gzippedSize,$newSize,${oldProverTime / step},${newProverTime / step}," +
      s"${oldVerifierTime / step},${newVerifierTime / step}")
  }

  def bench3(): Unit = {
    val newProver = new BatchAVLProver()
    val numMods = 1024 * 1024
    val batchSize = 1 // change to see different timings

    var mods = new Array[Modification](1024)
    for (i <- 0 until 1024) {
      for (j <- 0 until 1024)
        mods(j) = (Insert(Random.randomBytes(), Random.randomBytes(8)))
      val converted = Modification.convert(mods)
      val (t, d) = time {
        var j = 0
        while (j < 1024) {
          for (k <- 0 until batchSize)
            newProver.performOneModification(converted(j + k)._1, converted(j + k)._2)
          newProver.generateProof.toArray // this is what you give to the verifier, together with the OLD digest
          newProver.rootHash // this should go into the blockchain header -- NEW digest
          j += batchSize
        }
      }
      println(s"$i $t")
    }
  }

  def generateModifications(): Array[Modification] = {
    val mods = new Array[Modification](NumMods)

    for (i <- 0 until NumMods) {
      if (i == 0 || i < InitilaMods || i % 2 == 0) {
        // with prob ~.5 insert a new one, with prob ~.5 update an existing one
        mods(i) = Insert(Random.randomBytes(), Random.randomBytes(8))
        numInserts += 1
      } else {
        val j = Random.randomBytes(3)
        mods(i) = Update(mods((j(0).toInt.abs + j(1).toInt.abs * 128 + j(2).toInt.abs * 128 * 128) % i).key, Random.randomBytes(8))
      }
    }
    mods
  }


}
