package scorex.crypto.authds.avltree.batch

import org.scalameter.api._
import scorex.crypto.authds.avltree.batch.common.PreparedAVLBatchProver
import scorex.crypto.authds.avltree.batch.common.PreparedAVLBatchProver.Config

object AVLBatchProverMemorySpecification extends Bench.ForkedTime {
  override def measurer = new Measurer.MemoryFootprint

  private val startSize = 1000000
  private val finishSize = 3000000
  private val step = 1000000

  val ops = Gen.range("operations in tree")(startSize, finishSize, step)

  val KL = 32
  val VL = 8

  implicit val cfg = Config(KL, VL)

  performance of "AVLBatchProver" in {
    measure method s"memory footprint of prover tree" in {
      using(ops) config(
        exec.benchRuns -> 1,
        exec.maxWarmupRuns -> 2,
        exec.minWarmupRuns -> 2,
        exec.independentSamples -> 1,
        exec.outliers.retries -> 4
      ) in { PreparedAVLBatchProver.getProver }
    }
  }
}
