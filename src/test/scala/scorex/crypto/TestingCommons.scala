package scorex.crypto

import java.io.File

trait TestingCommons {
  val dirName = "/tmp/scorex-test/test/"
  val treeDir = new File(dirName)
  treeDir.mkdirs()

}
