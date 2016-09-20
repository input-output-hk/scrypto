package scorex.crypto

import java.io.File

import scorex.crypto.hash.Sha256

import scala.util.Random

trait TestingCommons {
  val dirName = "/tmp/scorex-test/test/"
  val treeDir = new File(dirName)
  treeDir.mkdirs()

  def genElements(howMany: Int, seed: Long): Seq[Array[Byte]] = {
    val r = Random
    r.setSeed(seed)
    (0 until howMany).map { l =>
      Sha256(r.nextString(16).getBytes)
    }
  }

  def time[R](block: => R): (Long, R) = {
    val t0 = System.currentTimeMillis()
    val result = block // call-by-name
    val t1 = System.currentTimeMillis()
    (t1 - t0, result)
  }

}
