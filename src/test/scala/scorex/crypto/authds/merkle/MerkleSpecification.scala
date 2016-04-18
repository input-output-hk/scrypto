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

  /*
  property("value returned from proofByIndex() is valid for a random dataset") {
    //fix block numbers for faster tests
    for (blocksNum <- List(7, 8, 9, 128)) {
      val smallInteger = Gen.choose(0, 0) // blocksNum - 1)
      val (treeDirName: String, _, tempFile: String) = generateFile(blocksNum)
      val (tree, segmentsStorage) = MerkleTreeImpl.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)

      forAll(smallInteger) { (index: Int) =>
        val leafOption = tree.proofByIndex(index).map { proof =>
          AuthDataBlock[DefaultHashFunction.type](segmentsStorage.get(index).get, proof)
        }
        leafOption should not be None
        val leaf = leafOption.get
        val resp = leaf.check(tree.rootHash)(DefaultHashFunction)
        resp shouldBe true
      }
    }
  }

  property("hash root is the same") {
    //fix block numbers for faster tests
    for (blocks <- List(7, 8, 9, 128)) {
      val (treeDirName: String, _, tempFile: String) = generateFile(blocks, "2")

      val (fileTree, segmentsStorage) = MerkleTreeImpl.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)
      val rootHash = fileTree.rootHash

      val tree = new MerkleTreeImpl(fileTree.storage, fileTree.nonEmptyBlocks, DefaultHashFunction)
      val newRootHash = tree.rootHash
      rootHash shouldBe newRootHash
    }
  } */

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