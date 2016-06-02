package scorex.crypto

import java.io.File

trait TestingCommons {
  val dirName = "/tmp/scorex-test/test/"
  val treeDir = new File(dirName)
  treeDir.mkdirs()

  def profile[R](block: => R): Long = {
    val start = System.currentTimeMillis()
    block
    System.currentTimeMillis() - start
  }

}
