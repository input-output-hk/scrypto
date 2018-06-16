package scorex.benchmarks

import org.openjdk.jmh.annotations._
import org.openjdk.jmh.infra.Blackhole
import scorex.benchmarks.Base16DecodeBenchmark.BenchmarkState
import scorex.crypto.encode.Base16

import scala.util.Random

class Base16EncodeBenchmark {
  @Benchmark
  def encode(bh: Blackhole): Unit = {
    bh.consume {
      (1 to 1000)
        .view
        .map { _ =>
          Random.nextString(200).getBytes()
        }
        .map(Base16.encode)
        .force
    }
  }

  @Benchmark
  def decode(state: BenchmarkState, bh: Blackhole): Unit = {
    bh.consume {
      state.xs.map(Base16.decode)
    }
  }


}

object Base16DecodeBenchmark {

  @State(Scope.Benchmark)
  class BenchmarkState {
    val xs: Seq[String] = (1 to 1000)
      .view
      .map(_ => Random.nextString(200).getBytes())
      .map(Base16.encode)
      .force
  }

}