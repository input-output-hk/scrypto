package scorex.crypto.authds.benchmarks

import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch._
import scorex.crypto.authds.avltree.{AVLModifyProof, AVLTree}
import scorex.utils.Random

object BatchingBenchmark extends App with TwoPartyTests {

  val InitilaMods = 1000000
  val NumMods = InitilaMods + 4096 * 64

  var digest = Array[Byte]()

  var numInserts = 0

  val mods = generateModifications()

  println(s"NumInserts = $numInserts")
  println("Step, Plain size, GZiped size, Batched size, Old apply time, New apply time, Old verify time, New verify time")

  bench2()

  def bench2(): Unit = {

    val steps = Seq(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 4096 * 2, 4096 * 4, 4096 * 8, 4096 * 16,
      4096 * 32, 4096 * 64)

    steps foreach { j =>
      val oldProver = new oldProver(new AVLTree(32))
      val newProver = new BatchAVLProver()

      val initialModifications = Modification.convert(mods.slice(0, InitilaMods))
      oldProver.applyUpdates(initialModifications)
      initialModifications foreach (m => newProver.performOneModification(m._1, m._2))
      newProver.generateProof
      digest = newProver.rootHash
      require(oldProver.rootHash sameElements digest)

      oneStep(InitilaMods, j, j, oldProver, newProver)
    }
  }

  def bench1(): Unit = {
    val oldProver = new oldProver(new AVLTree(32))
    val newProver = new BatchAVLProver()

    val initialModifications = Modification.convert(mods.slice(0, InitilaMods))
    oldProver.applyUpdates(initialModifications)
    initialModifications foreach (m => newProver.performOneModification(m._1, m._2))
    newProver.generateProof
    digest = newProver.rootHash
    require(oldProver.rootHash sameElements digest)

    val Step = 1000
    (InitilaMods until(NumMods, Step)) foreach { i =>
      oneStep(i, Step, i, oldProver, newProver)
    }
  }


  def oneStep(i: Int, step: Int, toPrint: Int, oldProver: oldProver, newProver: BatchAVLProver[_]): Unit = {
    System.gc()
    val converted = Modification.convert(mods.slice(i, i + step))

    val (oldProverTime, oldProves: Seq[AVLModifyProof]) = time {
      oldProver.applyUpdates(converted) match {
        case a: BatchSuccessSimple => a.proofs
        case BatchFailure(e) => throw e
      }
    }
    val oldBytes = oldProves.foldLeft(Array[Byte]()) { (a, b) =>
      a ++ b.proofSeq.map(_.bytes).reduce(_ ++ _)
    }
    val (oldVerifierTime, _) = time {
      var h = 0
      oldProves.foldLeft(digest) { (prevDigest, proof) =>
        val newDigest = proof.verify(prevDigest, converted(h)._2).get
        h = h + 1
        newDigest
      }
    }

    val oldSize = oldBytes.length.toFloat / step
    val gzippedSize = Gzip.compress(oldBytes).length.toFloat / step

    newProver.rootHash
    val (newProverTime, pf) = time {
      converted foreach (m => newProver.performOneModification(m._1, m._2))
      newProver.rootHash
      newProver.generateProof.toArray
    }
    val newSize = pf.length.toFloat / step

    val newVerifier = new BatchAVLVerifier(digest, pf)
    newVerifier.digest.get shouldEqual digest

    digest = oldProver.rootHash
    assert(newProver.rootHash sameElements digest)

    val (newVerifierTime, _) = time {
      converted foreach (m => newVerifier.verifyOneModification(m._1, m._2))
      newVerifier.digest
    }
    newVerifier.digest.get shouldEqual digest
    println(s"$toPrint,$oldSize,$gzippedSize,$newSize,$oldProverTime,$newProverTime,$oldVerifierTime,$newVerifierTime")
  }

  def generateModifications(): Array[Modification] = {
    val mods = new Array[Modification](NumMods)
    mods(0) = Insert(Random.randomBytes(), Random.randomBytes(8))

    for (i <- 1 until NumMods) {
      if (scala.util.Random.nextBoolean()) {
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
