package scorex.crypto.authds.merkle.serialization

import org.scalatest.propspec.AnyPropSpec
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds.merkle.{BatchMerkleProof, Leaf, MerkleTree}
import scorex.crypto.authds.{LeafData, Side, TwoPartyTests}
import scorex.crypto.hash.{Digest, Digest32, Keccak256}

import scala.util.Random

class BatchMerkleProofSerializationSpecification extends AnyPropSpec with ScalaCheckDrivenPropertyChecks with TwoPartyTests {

  type D = Digest32
  type HF = Keccak256.type
  implicit val hf: HF = Keccak256
  private val LeafSize = 32

  property("Batch proof serialization + deserialization") {
    val r = new Random()
    val serializer = new BatchMerkleProofSerialization[D]
    forAll(smallInt) { N: Int =>
      whenever(N > 0) {
        val d = (0 until N).map(_ => LeafData @@ scorex.utils.Random.randomBytes(LeafSize))
        val tree = MerkleTree(d)
        val randIndices = (0 until r.nextInt(N + 1) + 1)
          .map(_ => r.nextInt(N))
          .distinct
          .sorted
        val compactMultiproof = tree.proofByIndices(randIndices).get

        val rebuiltMultiproof = BatchMerkleProof(
          serializer.indicesFromBytes(serializer.indicesToBytes(compactMultiproof.indices)),
          serializer.proofsFromBytes(serializer.proofsToBytes(compactMultiproof.proofs)))

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

  property("indices serialization + deserialization") {
    val r = new Random()
    val serializer = new BatchMerkleProofSerialization[D]
    forAll(smallInt) { N: Int =>
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
    val serializer = new BatchMerkleProofSerialization[D]
    forAll(smallInt) { N: Int =>
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
