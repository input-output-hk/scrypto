package scorex.crypto.authds.merkle.versioned

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.merkle.CommonTreeFunctionality
import scorex.crypto.authds.merkle.MerkleTree._
import scorex.utils.Random


class VersionedMerkleSpecification
  extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers
  with CommonTreeFunctionality {

  property("two appends of the same contents are commutative") {
    def generateAppend() = MerklizedSeqAppend(Random.randomBytes(200))

    for (blocks <- List(7, 8, 9, 128)) {

      val (treeDirName: String, _, tempFile: String) = generateFile(blocks, "2")

      val vms1 = MvStoreVersionedMerklizedSeq.fromFile(tempFile, treeDirName, 1024, DefaultHashFunction)
      val vms2 = MvStoreVersionedMerklizedSeq.fromFile(tempFile, treeDirName+"1", 1024, DefaultHashFunction)

      vms1.rootHash shouldBe vms2.rootHash

      val upd1 = Seq(generateAppend(), generateAppend())

      vms1.update(Nil, upd1)
      vms1.update(Nil, upd1)

      vms2.update(Nil, upd1)
      vms2.update(Nil, upd1)

      vms1.rootHash shouldBe vms2.rootHash
    }
  }

}
