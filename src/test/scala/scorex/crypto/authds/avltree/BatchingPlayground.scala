package scorex.crypto.authds.avltree

import scorex.crypto.authds.avltree.batch._
import scorex.utils.Random

object BatchingPlayground extends App {


// TODO: Add a test that runs a prover on no changes and a verifier on no changes, both on an empty tree and on a modified tree
// TODO: Add a test that modifies directions and sees verifier reject

  val tree = new AVLTree(32)
  var digest = tree.rootHash()
  val oldProver = new oldProver(tree)

  val newProver = new BatchAVLProver()
  assert (newProver.rootHash sameElements digest)

  val numMods = 2000000

  val mods = new Array[Modification](numMods)
  mods(0) = Insert(Random.randomBytes(), Random.randomBytes(8))

  var numInserts = 0
  for (i <- 1 until numMods) {
    if((Random.randomBytes(1))(0).toInt.abs<64) { // with prob ~.5 insert a new one, with prob ~.5 update an existing one
      mods(i) = Insert(Random.randomBytes(), Random.randomBytes(8))
      numInserts+=1
    }
    else {
      val j = Random.randomBytes(3)
      mods(i) = Update(mods((j(0).toInt.abs+j(1).toInt.abs*128+j(2).toInt.abs*128*128) % i).key, Random.randomBytes(8))
    }
  }

  var i = 0
  while (i<numMods) {
    var j =  1000+i //(Random.randomBytes(1))(0).toInt.abs + i
    if (j>numMods) j = numMods
    println(j)
    val currentMods = new scala.collection.mutable.ArrayBuffer[Modification](j-i)
    while(i<j) {
      currentMods += mods(i)
      i+=1
    }

    oldProver.applyBatchSimple(currentMods) match {
      case bss: BatchSuccessSimple =>
        assert(new oldVerifier(digest).verifyBatchSimple(currentMods, bss))
      case bf: BatchFailure =>
        println(bf.error)
        assert(false)
    }

    Modification.convert(currentMods) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
    val pf = newProver.generateProof.toArray

    println(pf.length)

    val newVerifier = new BatchAVLVerifier(digest, pf)
    newVerifier.digest match {
      case None =>
        println("ERROR VERIFICATION FAILED TO CONSTRUCT THE TREE")
        assert(false)
      case Some(d) =>
        assert (d sameElements digest) // Tree built successfully
    }

    digest = oldProver.rootHash
    assert (newProver.rootHash sameElements digest)
    Modification.convert(currentMods) foreach (m => newVerifier.verifyOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
    newVerifier.digest match {
      case None =>
        println("ERROR VERIFICATION FAIL")
        assert(false)
      case Some(d) =>
        assert (d sameElements digest)
    }
  }
  print("NumInserts = ")
  println(numInserts)

}
