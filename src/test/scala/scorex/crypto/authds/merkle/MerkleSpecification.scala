package scorex.crypto.authds.merkle

import org.scalacheck.Gen
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.merkle.MerkleTree.DefaultHashFunction
import scorex.crypto.authds.merkle.versioned.{MvStoreVersionedMerkleTree, MvStoreVersionedMerklizedSeq}

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

  property("fromFile construction correct") {
    for (blocksNum <- List(7, 8, 9, 128)) {
      val (treeDirName: String, _, tempFile: String) = generateFile(blocksNum)
      val vms = MvStoreVersionedMerklizedSeq.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)
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
      val vms = MvStoreVersionedMerklizedSeq.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)

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

      val vms = MvStoreVersionedMerklizedSeq.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)
      val rootHash = vms.rootHash

      val tree = MvStoreVersionedMerkleTree(vms.seq, None, DefaultHashFunction)
      val treeRootHash = tree.rootHash

      rootHash shouldBe treeRootHash
    }
  }
}