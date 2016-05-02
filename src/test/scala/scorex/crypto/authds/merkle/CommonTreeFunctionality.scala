package scorex.crypto.authds.merkle

import java.io.{File, FileOutputStream}

import scorex.crypto.authds.merkle.versioned.MvStoreVersionedMerklizedSeq
import scorex.crypto.authds.storage.MvStoreVersionedBlobStorage
import scorex.crypto.hash.Sha256

import scala.util.Random

trait CommonTreeFunctionality {
  def generateFile(blocks: Int, subdir: String = "1"): (String, File, String) = {
    val treeDirName = "/tmp/scorex-test/test/" + subdir + "/"
    val treeDir = new File(treeDirName)
    val tempFile = treeDirName + "/data.file"

    val data = new Array[Byte](1024 * blocks)
    Random.nextBytes(data)
    treeDir.mkdirs()
    for (file <- treeDir.listFiles) file.delete

    val fos = new FileOutputStream(tempFile)
    fos.write(data)
    fos.close()
    (treeDirName, treeDir, tempFile)
  }

  def helloWorldTree() = {
    val value = "hello world".getBytes
    val storage = new MvStoreVersionedBlobStorage(None)
    storage.set(0, value)
    storage.set(1, value)
    storage.set(2, value)
    storage.set(3, value)
    storage.commit()

    MvStoreVersionedMerklizedSeq.apply(None, storage, 1, Sha256)
  }
}
