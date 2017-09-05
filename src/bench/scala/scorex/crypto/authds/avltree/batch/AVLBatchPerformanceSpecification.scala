package scorex.crypto.authds.avltree.batch

import org.scalameter.api._
import scorex.crypto.authds.avltree.batch.common.PreparedAVLBatchProver.Config
import scorex.crypto.authds.avltree.batch.common.{OperationsOps, PreparedAVLBatchProver}

object AVLBatchPerformanceSpecification extends Bench.ForkedTime with OperationsOps {

  protected val start = 100000
  protected val inserts = 2000
  protected val deletes = 1000
  protected val steps = 50
  protected val end = steps * (inserts + deletes) + start
  protected val step = inserts + deletes

  protected val KL = 8
  protected val VL = 32

  implicit val config: Config = PreparedAVLBatchProver.Config(KL, VL)

  val opsCount =
    Gen.range(s"Applying $inserts inserts and $deletes deletes to tree with $start operations")(start, end, step)

  val heatedProver = PreparedAVLBatchProver.getProver(start)

  performance of "AVLBatchProver" in {
    measure method "perform batch of operations" in {
      using(opsCount) config(
        exec.benchRuns -> 2,
        exec.maxWarmupRuns -> 2,
        exec.minWarmupRuns -> 2,
        exec.independentSamples -> 2
      ) in { index =>
        val r = index until index + step
        val in = generateInserts(r)
        val out = generateDeletes(in, deletes)
        val ops = in ++ out
        ops.foreach(heatedProver.performOneOperation)
        heatedProver.generateProof
      }
    }
  }

}
