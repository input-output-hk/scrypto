package scorex.crypto.authds.benchmarks

import scorex.crypto.authds.TwoPartyTests
import scorex.crypto.authds.avltree.batch._
import scorex.crypto.authds.avltree.{AVLModifyProof, AVLTree}
import scorex.utils.Random

object BatchingBenchmark extends App with TwoPartyTests {

  val Step = 1000
  val NumMods = 2000000

  val oldProver = new oldProver(new AVLTree(32))

  val newProver = new BatchAVLProver()
  var digest = newProver.rootHash

  var numInserts = 0

  val mods = generateModifications()

  println("Step, Plain size, GZiped size, Batched size, Old apply time, New apply time, Old verify time, New verify time")
  (0 until(NumMods, Step)) foreach { i =>
    System.gc()
    val currentMods = mods.slice(i, i + Step)
    val converted = Modification.convert(currentMods)

    val (oldProverTime, oldProves: Seq[AVLModifyProof]) = time {
      oldProver.applyUpdates(converted).asInstanceOf[BatchSuccessSimple].proofs
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

    val oldSize = oldBytes.length.toFloat / Step
    val gzippedSize = Gzip.compress(oldBytes).length.toFloat / Step

    newProver.rootHash
    val (newProverTime, pf) = time {
      converted foreach (m => newProver.performOneModification(m._1, m._2))
      newProver.rootHash
      newProver.generateProof.toArray
    }
    val newSize = pf.length.toFloat / Step

    val newVerifier = new BatchAVLVerifier(digest, pf)
    newVerifier.digest.get shouldEqual digest

    digest = oldProver.rootHash
    assert(newProver.rootHash sameElements digest)

    val (newVerifierTime, _) = time {
      converted foreach (m => newVerifier.verifyOneModification(m._1, m._2))
      newVerifier.digest
    }
    newVerifier.digest.get shouldEqual digest
    println(s"$i,$oldSize,$gzippedSize,$newSize,$oldProverTime,$newProverTime,$oldVerifierTime,$newVerifierTime")
  }
  print(s"NumInserts = $numInserts")

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
