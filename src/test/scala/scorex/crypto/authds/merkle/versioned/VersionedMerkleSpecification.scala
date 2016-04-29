package scorex.crypto.authds.merkle.versioned

import org.scalacheck.Gen
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.merkle.CommonTreeFunctionality
import scorex.crypto.authds.merkle.MerkleTree._



class VersionedMerkleSpecification
  extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers
  with CommonTreeFunctionality {

  property("two appends of the same contents are commutative") {
    for (blocks <- List(7, 8, 9, 128)) {

      val (_, _, tempFile: String) = generateFile(blocks, "3")

      val vms1 = MvStoreVersionedMerklizedSeq.fromFile(tempFile, None, 1024, DefaultHashFunction)
      val vms2 = MvStoreVersionedMerklizedSeq.fromFile(tempFile, None, 1024, DefaultHashFunction)

      vms1.rootHash shouldBe vms2.rootHash

      forAll(Gen.listOf(Gen.alphaStr)) { strings:List[String] =>
        val upd = strings.map(_.getBytes).map(MerklizedSeqAppend.apply)

        vms1.update(Nil, upd)
        vms1.update(Nil, upd)

        vms2.update(Nil, upd)
        vms2.update(Nil, upd)

        vms1.rootHash shouldBe vms2.rootHash
      }
    }
  }

}
