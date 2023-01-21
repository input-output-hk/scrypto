package scorex.benchmarks

import org.openjdk.jmh.annotations._
import org.openjdk.jmh.infra.Blackhole
import org.openjdk.jmh.profile.GCProfiler
import org.openjdk.jmh.runner.options.OptionsBuilder
import org.openjdk.jmh.runner.{Runner, RunnerException}
import scorex.benchmarks.Base16Benchmark.BenchmarkState
import scorex.crypto.encode.Base16

import scala.util.Random


class Base16Benchmark {
  @Benchmark
  def encode(state: BenchmarkState, bh: Blackhole): Unit = {
    bh.consume {
      state.xab.map(Base16.encode)
    }
  }

  @Benchmark
  def decode(state: BenchmarkState, bh: Blackhole): Unit = {
    bh.consume {
      state.xs.map(Base16.decode)
    }
  }
}

object Base16Benchmark {

  @throws[RunnerException]
  def main(args: Array[String]): Unit = {
    val opt = new OptionsBuilder()
      .include(".*" + classOf[Base16Benchmark].getSimpleName + ".*")
      .forks(1)
      .addProfiler(classOf[GCProfiler])
      .build
    new Runner(opt).run
  }

  @State(Scope.Benchmark)
  class BenchmarkState {
    val xs: Seq[String] = (1 to 1000)
      .view
      .map(_ => Random.nextString(200).getBytes("UTF-8"))
      .map(Base16.encode)
      .force

    val xab: Seq[Array[Byte]] = (1 to 1000)
      .view
      .map(_ => Random.nextString(200).getBytes("UTF-8"))
      .force
  }

}