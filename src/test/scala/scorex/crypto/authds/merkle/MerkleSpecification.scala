package scorex.crypto.authds.merkle

import java.io.{File, FileOutputStream}

import org.scalacheck.Gen
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}

import scala.util.Random

class MerkleSpecification extends PropSpec with PropertyChecks with GeneratorDrivenPropertyChecks with Matchers {

  property("fromFile construction") {
    for (blocksNum <- List(7, 8, 9, 128)) {
      val (treeDirName: String, _, tempFile: String) = generateFile(blocksNum)
      val mvs = MvStoreVersionedMerklizedSeq.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)
      (0L to mvs.size - 1).foreach { idx =>
        val same = DefaultHashFunction(mvs.seq.get(idx).get) sameElements mvs.tree.getHash(0 -> idx).get
        same should be(true)
      }
    }
  }

  property("value returned from proofByIndex() is valid for a random dataset") {
    for (blocksNum <- List(7, 8, 9, 128)) {
      val smallInteger = Gen.choose(0, blocksNum - 1)
      val (treeDirName: String, _, tempFile: String) = generateFile(blocksNum)
      val vms = MvStoreVersionedMerklizedSeq.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)

      forAll(smallInteger) { (index: Int) =>
        println("size: " + vms.size + " index: " + index)
        val leaf = vms.tree.proofByIndex(index).map { merklePath =>
          merklePath.hashes.size shouldBe vms.tree.height
          AuthDataBlock[DefaultHashFunction.type](vms.seq.get(index).get, merklePath)
        }.get
        val resp = leaf.check(vms.rootHash)(DefaultHashFunction)
        if (!resp) println("!!! size: " + vms.size + " index: " + index)
        resp shouldBe true
      }
    }
  }

  property("hash root is the same") {
    for (blocks <- List(7, 8, 9, 128)) {
      val (treeDirName: String, _, tempFile: String) = generateFile(blocks, "2")

      val mvs = MvStoreVersionedMerklizedSeq.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)
      val rootHash = mvs.rootHash

      val tree = MvStoreVersionedMerkleTree(mvs.seq, None, DefaultHashFunction)
      val treeRootHash = tree.rootHash
      rootHash shouldBe treeRootHash
    }
  }

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
}