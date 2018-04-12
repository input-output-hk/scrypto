package scorex.crypto.authds.avltree.batch.serialization

import org.scalacheck.Gen
import org.scalatest.PropSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import scorex.crypto.authds.avltree.batch.{BatchAVLProver, Insert}
import scorex.crypto.authds.{ADKey, ADValue, TwoPartyTests}
import scorex.crypto.hash.{Blake2b256, _}
import scorex.utils.Random

class AVLBatchSerializationSpecification extends PropSpec with GeneratorDrivenPropertyChecks with TwoPartyTests {

  val InitialTreeSize = 1000
  val KL = 26
  val VL = 8
  val HL = 32
  type D = Digest32
  type HF = Blake2b256.type
  implicit val hf: HF = Blake2b256

  def randomKey(size: Int = 32): ADKey = ADKey @@ Random.randomBytes(size)

  def randomValue(size: Int = 32): ADValue = ADValue @@ Random.randomBytes(size)

  private def generateProver(size: Int = InitialTreeSize): BatchAVLProver[D, HF] = {
    val prover = new BatchAVLProver[D, HF](KL, None)
    val keyValues = (0 until size) map { i =>
      (ADKey @@ Blake2b256(i.toString.getBytes).take(KL), ADValue @@ (i.toString.getBytes))
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))
    prover.generateProof()
    prover
  }

  property("slice to pieces and combine tree back") {
    forAll(Gen.choose(100, 100000)) { treeSize: Int =>
      val tree = generateProver(treeSize)
      val digest = tree.digest
      val serializer = new BatchAVLProverSerializer[D, HF]
      val sliced = serializer.slice(tree)
      val recovered = serializer.combine(sliced).get
      recovered.digest shouldEqual digest
    }
  }


}
