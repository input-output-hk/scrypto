package scorex.benchmarks

import java.util.concurrent.TimeUnit

import com.google.common.primitives.Shorts
import org.openjdk.jmh.annotations._
import org.openjdk.jmh.infra.Blackhole
import scorex.utils.ByteArray

import scala.util.Random


object ByteArrayComparePerformance {

  def compare(buffer1: Array[Byte], buffer2: Array[Byte]): Int = if (buffer1 sameElements buffer2) {
    0
  } else {
    val end1: Int = if (buffer1.length < buffer2.length) buffer1.length else buffer2.length
    var i: Int = 0
    while (i < end1) {
      val a: Int = buffer1(i) & 0xff
      val b: Int = buffer2(i) & 0xff
      if (a != b) {
        return a - b
      }
      i = i + 1
    }
    buffer1.length - buffer2.length
  }

  trait BenchmarkState {
    def vectors: IndexedSeq[Array[Byte]]
  }

  @State(Scope.Thread)
  class Random32Bytes extends BenchmarkState {
    val vectors: IndexedSeq[Array[Byte]] = (0 to 1000).map { _ =>
      val bs = new Array[Byte](32)
      Random.nextBytes(bs)
      bs
    }
  }

  @State(Scope.Thread)
  class WorstCase32Bytes extends BenchmarkState {
    val vectors: IndexedSeq[Array[Byte]] = (0 to 1000).map { i =>
      new Array[Byte](30) ++ Shorts.toByteArray(i.toShort)
    }
  }

  def compareWithUnsignedBytes(state: BenchmarkState, bh: Blackhole): Unit =
    state.vectors.indices.init foreach { i =>
      bh.consume(ByteArray.compare(state.vectors(i), state.vectors(i + 1)))
    }

  def legacyCompare(state: BenchmarkState, bh: Blackhole): Unit =
    state.vectors.indices.init foreach { i =>
      bh.consume(compare(state.vectors(i), state.vectors(i + 1)))
    }
}


@BenchmarkMode(Array(Mode.Throughput))
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(1)
class ByteArrayComparePerformance {

  import ByteArrayComparePerformance._

  @Benchmark
  def compareWithUnsignedBytesRandom(state: Random32Bytes, bh: Blackhole): Unit =
    compareWithUnsignedBytes(state, bh)

  @Benchmark
  def legacyCompareRandom(state: Random32Bytes, bh: Blackhole): Unit =
    legacyCompare(state, bh)

  @Benchmark
  def compareWithUnsignedBytesWorstCase(state: WorstCase32Bytes, bh: Blackhole): Unit =
    compareWithUnsignedBytes(state, bh)

  @Benchmark
  def legacyCompareWorstCase(state: WorstCase32Bytes, bh: Blackhole): Unit =
    legacyCompare(state, bh)

}
