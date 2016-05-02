package scorex.crypto.authds.merkle

import org.scalacheck.Gen
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.merkle.MerkleTree.DefaultHashFunction
import scorex.crypto.authds.merkle.versioned.{MvStoreVersionedMerkleTree, MvStoreVersionedMerklizedSeq}
import scorex.crypto.authds.storage.MvStoreVersionedBlobStorage
import scorex.crypto.encode.Base16
import scorex.crypto.hash.Sha256

/**
  * For now, the only Merkle tree option is versioned one. When a static Merkle tree will
  * be implemented, tests for it will be here, and versioned-specific functionality should be
  * moved to a separate class
  */

class MerkleSpecification
  extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers
  with CommonTreeFunctionality {

  //calculates root hash of the tree consisting of
  //4 leafs having value b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
  property("sample with SHA-256"){

    val vms = helloWorldTree
    //      0ba
    //  47a     47a
    // b94 b94 b94 b94
    vms.tree.getHash(0 -> 0).get shouldBe Base16.decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
    vms.tree.rootHash shouldBe Base16.decode("0ba8ad6fc2a7c94abcd2d4128720c5697cf147310ae82287270d56beaf8702f1")
  }

  property("fromFile construction correct") {
    for (blocksNum <- List(7, 8, 9, 128)) {
      val (treeDirName: String, _, tempFile: String) = generateFile(blocksNum)
      val vms = MvStoreVersionedMerklizedSeq.fromFile(tempFile, Some(treeDirName), 1024, DefaultHashFunction)
      (0L to vms.size - 1).foreach { idx =>
        val same = DefaultHashFunction(vms.seq.get(idx).get) sameElements vms.tree.getHash(0 -> idx).get
        same should be(true)
      }
    }
  }

  property("value returned from proofByIndex() is valid for a random dataset") {
    for (blocksNum <- List(7, 8, 9, 128)) {
      val smallInteger = Gen.choose(0, blocksNum - 1)
      val (treeDirName: String, _, tempFile: String) = generateFile(blocksNum)
      val vms = MvStoreVersionedMerklizedSeq.fromFile(tempFile, None, 1024, DefaultHashFunction)

      forAll(smallInteger) { (index: Int) =>
        val leaf = vms.tree.proofByIndex(index).map { merklePath =>
          merklePath.hashes.size shouldBe vms.tree.height
          AuthData[DefaultHashFunction.type](vms.seq.get(index).get, merklePath)
        }.get
        leaf.check(vms.rootHash)(DefaultHashFunction) shouldBe true
      }
    }
  }

  property("hash root is the same") {
    for (blocks <- List(7, 8, 9, 128)) {
      val (treeDirName: String, _, tempFile: String) = generateFile(blocks, "2")

      val vms = MvStoreVersionedMerklizedSeq.fromFile(tempFile, Some(treeDirName), 1024, DefaultHashFunction)
      val rootHash = vms.rootHash

      val tree = MvStoreVersionedMerkleTree(vms.seq, None, DefaultHashFunction)
      val treeRootHash = tree.rootHash

      rootHash shouldBe treeRootHash
    }
  }
}