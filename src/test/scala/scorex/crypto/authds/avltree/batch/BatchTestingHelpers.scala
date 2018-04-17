package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.{ADKey, ADValue}
import scorex.crypto.authds.avltree.batch.BatchingPlayground.arrayToString
import scorex.crypto.hash.{Blake2b256, Digest32}
import scorex.utils.Random

trait BatchTestingHelpers extends ToStringHelper {

  val InitialTreeSize = 1000

  val KL = 32
  val VL = 8
  type D = Digest32
  type HF = Blake2b256.type

  def randomKey(size: Int = 32): ADKey = ADKey @@ Random.randomBytes(size)

  def randomValue(size: Int = 32): ADValue = ADValue @@ Random.randomBytes(size)

  def generateProver(size: Int = InitialTreeSize): BatchAVLProver[D, HF] = {
    val prover = new BatchAVLProver[D, HF](KL, None)
    val keyValues = (0 until size) map { i =>
      (ADKey @@ Blake2b256(i.toString.getBytes).take(KL), ADValue @@ (i.toString.getBytes))
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))
    prover.generateProof()
    prover
  }


  def pathToString(path: Seq[ProverNodes[D]]): String = {
    def loop(prevNode: ProverNodes[D], remaining: Seq[ProverNodes[D]], acc: Seq[String]): Seq[String] = {
      if (remaining.nonEmpty) {
        prevNode match {
          case pn: InternalProverNode[D] =>
            val n = remaining.head
            val direction = if (n.label sameElements pn.left.label) "L" else "R"


            val newAcc = s"$direction-${arrayToString(n.label)}" +: acc
            loop(n, remaining.tail, newAcc)
          case _ => ???
        }
      } else {
        acc
      }
    }

    loop(path.head, path.tail, Seq(arrayToString(path.head.label))).reverse.mkString(",")
  }

}
