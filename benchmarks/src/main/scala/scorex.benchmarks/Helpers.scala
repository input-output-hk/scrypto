package scorex.benchmarks

import com.google.common.primitives.Longs
import scorex.crypto.authds.{ADKey, ADValue}
import scorex.crypto.authds.avltree.batch.{BatchAVLProver, Insert, Operation, Remove}
import scorex.crypto.hash.{Blake2b256, Digest32}

import scala.util.Random

object Helpers {

  val kl = 8
  val vl = 16

  def generateInserts(r: Range): Seq[Operation] =
    r.map { i =>
      val key = new Array[Byte](kl)
      val k = Longs.toByteArray(i)
      k.copyToArray(key)
      Insert(ADKey @@ key, ADValue @@ k.take(kl))
    }

  def generateDeletes(inserts: Seq[Operation], count: Int): Seq[Operation] =
    Random.shuffle(inserts).take(count).map { in => Remove(in.key)}

  type D = Digest32
  type HF = Blake2b256.type
  type Prover = BatchAVLProver[D, HF]

  private val STEP = 2000

  def getProver(operationsCount: Int): Prover = {

    val prover = new BatchAVLProver[D, HF](keyLength = kl, valueLengthOpt = Some(vl))

    Range(0, operationsCount, STEP).map { index =>
      (index until index + STEP).map { i =>
        val key = Longs.toByteArray(i.toLong)
        val value = key

        val fullKey = Array.fill(kl - 8)(0: Byte) ++ key
        val fullValue = Array.fill(vl - 8)(0: Byte) ++ value

        val insert = Insert(ADKey @@ fullKey, ADValue @@ fullValue)
        prover.performOneOperation(insert)
      }
      prover.generateProof()
    }
    prover
  }

}
