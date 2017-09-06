package scorex.crypto.authds.avltree.batch.common

import com.google.common.primitives.Longs
import scorex.crypto.authds.{ADKey, ADValue}
import scorex.crypto.authds.avltree.batch.{BatchAVLProver, Insert}
import scorex.crypto.hash.{Blake2b256Unsafe, Digest32}

object PreparedAVLBatchProver {
  type D = Digest32
  type HF = Blake2b256Unsafe

  private val STEP = 20

  case class Config(kl: Int, vl: Int)

  def getProver(operationsCount: Int)(implicit config: Config): BatchAVLProver[D, HF] = {

    val prover = new BatchAVLProver[D, HF](keyLength = config.kl, valueLengthOpt = Some(config.vl))

    Range(0, operationsCount, STEP).map { index =>
      (index until index + STEP).map { i =>
        val key = Longs.toByteArray(i.toLong)
        val value = key

        val fullKey = Array.fill(config.kl - 8)(0: Byte) ++ key
        val fullValue = Array.fill(config.vl - 8)(0: Byte) ++ value

        val insert = Insert(ADKey @@ fullKey, ADValue @@ fullValue)
        prover.performOneOperation(insert)
      }
      prover.generateProof()
    }
    prover
  }
}
