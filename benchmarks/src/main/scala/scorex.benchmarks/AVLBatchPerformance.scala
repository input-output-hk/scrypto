package scorex.benchmarks

import java.util.concurrent.TimeUnit

import org.openjdk.jmh.annotations._
import scorex.benchmarks.Helpers._
import scorex.crypto.authds.avltree.batch.Operation

object AVLBatchPerformance {

  @State(Scope.Thread)
  class Basic(proverCnt: Int, opsCnt: Int) {

    val preparedOperations = proverCnt
    val operationsToApply = opsCnt

    var prover: Prover = _
    var operations: Seq[Operation] = _

    @Setup(Level.Iteration)
    def up: Unit = {
      prover = getProver(preparedOperations)
      val inserts = generateInserts(preparedOperations until (preparedOperations + operationsToApply))
      operations = inserts
    }
  }

  class StateWith1000000 extends Basic(1000000, 100000)

  class StateWith2000000 extends Basic(2000000, 100000)

  class StateWith4000000 extends Basic(4000000, 100000)

  class StateWith8000000 extends Basic(8000000, 100000)

  class StateWith16000000 extends Basic(16000000, 100000)

  class StateWith32000000 extends Basic(32000000, 100000)
}

@BenchmarkMode(Array(Mode.AverageTime))
@OutputTimeUnit(TimeUnit.SECONDS)
@Fork(1)
class AVLBatchPerformance {
  import AVLBatchPerformance._

  @Benchmark
  def apply100KinBatchesOf2KToProverWith1M(s: StateWith1000000): Unit = {
    import s._
    operations.grouped(2000).foreach { batch =>
      batch.foreach(prover.performOneOperation)
      prover.generateProof()
    }
  }

  @Benchmark
  def apply100KinBatchesOf2KToProverWith2M(s: StateWith2000000): Unit = {
    import s._
    operations.grouped(2000).foreach { batch =>
      batch.foreach(prover.performOneOperation)
      prover.generateProof()
    }
  }

  @Benchmark
  def apply100KinBatchesOf2KToProverWith4M(s: StateWith4000000): Unit = {
    import s._
    operations.grouped(2000).foreach { batch =>
      batch.foreach(prover.performOneOperation)
      prover.generateProof()
    }
  }

  @Benchmark
  def apply100KinBatchesOf2KToProverWith8M(s: StateWith8000000): Unit = {
    import s._
    operations.grouped(2000).foreach { batch =>
      batch.foreach(prover.performOneOperation)
      prover.generateProof()
    }
  }

  @Benchmark
  def apply100KinBatchesOf2KToProverWith16M(s: StateWith16000000): Unit = {
    import s._
    operations.grouped(2000).foreach { batch =>
      batch.foreach(prover.performOneOperation)
      prover.generateProof()
    }
  }

  @Benchmark
  def apply100KinBatchesOf2KToProverWith32M(s: StateWith32000000): Unit = {
    import s._
    operations.grouped(2000).foreach { batch =>
      batch.foreach(prover.performOneOperation)
      prover.generateProof()
    }
  }

}
