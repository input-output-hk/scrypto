package scorex.crypto.authds.merkle.serialization

import org.scalatest.TryValues
import org.scalatest.propspec.AnyPropSpec
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds.merkle.{MerkleTree, Leaf}
import scorex.crypto.authds.{Side, TwoPartyTests, LeafData}
import scorex.crypto.hash.{Digest32, Digest}

import scala.util.Random

class BatchMerkleProofSerializerSpecification extends AnyPropSpec
  with ScalaCheckDrivenPropertyChecks
  with TwoPartyTests
  with TryValues {

  type D = Digest32
  type HF = scorex.crypto.hash.Blake2b256.type
  implicit val hf: HF = scorex.crypto.hash.Blake2b256
  private val LeafSize = 32

  property("Batch proof serialization + deserialization") {
    val r = new Random()
    val serializer = new BatchMerkleProofSerializer[D, HF]
    forAll(smallInt) { (N: Int) =>
      whenever(N > 0) {
        val d = (0 until N).map(_ => LeafData @@ scorex.utils.Random.randomBytes(LeafSize))
        val tree = MerkleTree(d)
        val randIndices = (0 until r.nextInt(N + 1) + 1)
          .map(_ => r.nextInt(N))
          .distinct
          .sorted

        val compactMultiproof = tree.proofByIndices(randIndices).get
        val serializedBytes = serializer.serialize(compactMultiproof)
        val rebuiltMultiproof = serializer.deserialize(serializedBytes).get

        serializedBytes.length shouldEqual
          (8 + (compactMultiproof.proofs.size * 33) + (compactMultiproof.indices.size * 36))
        compactMultiproof.indices.zipWithIndex.foreach { case ((index, hash), i) =>
          val res = rebuiltMultiproof.indices.apply(i)
          index shouldEqual res._1
          hash shouldEqual res._2
        }
        compactMultiproof.proofs.zipWithIndex.foreach { case ((digest, side), i) =>
          val res = rebuiltMultiproof.proofs.apply(i)
          digest shouldEqual res._1
          side shouldEqual res._2
        }
      }
    }
  }

  property(testName = "empty deserialization input") {
    val serializer = new BatchMerkleProofSerializer[D, HF]
    val res = serializer.deserialize(scorex.utils.Random.randomBytes(2))
    res.failure.exception should have message "Deserialization error, empty input."
  }

  property(testName = "invalid deserialization input") {
    val serializer = new BatchMerkleProofSerializer[D, HF]
    val res = serializer.deserialize(scorex.utils.Random.randomBytes(9))
    res.failure.exception should have message "Deserialization error, invalid input."
  }

  property("indices serialization + deserialization") {
    val r = new Random()
    val serializer = new BatchMerkleProofSerializer[D, HF]
    forAll(smallInt) { (N: Int) =>
      whenever(N > 0) {

        val d = (0 until N).map(_ => LeafData @@ scorex.utils.Random.randomBytes(LeafSize))
        val randIndices = (0 until r.nextInt(N + 1) + 1)
          .map(_ => r.nextInt(N))
          .sorted
          .distinct
        val indices = randIndices zip randIndices.map(i => Leaf(d.apply(i)).hash)

        val serializedIndices: Array[Byte] = serializer.indicesToBytes(indices)
        val deserializedIndices: Seq[(Int, Digest)] = serializer.indicesFromBytes(serializedIndices)

        indices.zipWithIndex.foreach { case ((index, hash), i) =>
          val res = deserializedIndices.apply(i)
          index shouldEqual res._1
          hash shouldEqual res._2
        }
      }
    }
  }

  property("proofs serialization + deserialization") {
    val r = new Random()
    val serializer = new BatchMerkleProofSerializer[D, HF]
    forAll(smallInt) { (N: Int) =>
      whenever(N > 0) {

        val proofs: Seq[(Digest, Side)] = (0 until N)
          .map(_ => LeafData @@ scorex.utils.Random.randomBytes(LeafSize))
          .map(l => (Leaf(l).hash, Side @@ r.nextInt(2).toByte))

        val serializedProofs: Array[Byte] = serializer.proofsToBytes(proofs)
        val deserializedProofs: Seq[(Digest, Side)] = serializer.proofsFromBytes(serializedProofs)

        proofs.zipWithIndex.foreach { case ((digest, side), i) =>
          val res = deserializedProofs.apply(i)
          digest shouldEqual res._1
          side shouldEqual res._2
        }
      }
    }
  }
}
