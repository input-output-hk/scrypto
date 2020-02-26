package scorex.crypto.authds.avltree.batch

import com.google.common.primitives.Longs
import org.scalacheck.commands.Commands
import org.scalacheck.{Gen, Prop}
import org.scalatest.propspec.AnyPropSpec
import scorex.crypto.authds._
import scorex.crypto.hash.{Blake2b256, Digest32}
import scorex.utils.{Random => RandomBytes}

import scala.util.{Failure, Random, Success, Try}

class AVLBatchStatefulSpecification extends AnyPropSpec {

  property("BatchAVLProver: prove and verify") {
    AVLCommands.property().check
  }
}

object AVLCommands extends Commands {

  val KL = 32
  val VL = 8

  val MINIMUM_OPERATIONS_LENGTH = 10
  val MAXIMUM_GENERATED_OPERATIONS = 10

  val UPDATE_FRACTION = 2
  val REMOVE_FRACTION = 4

  type T = Digest32
  type HF = Blake2b256.type

  case class Operations(operations: List[Operation]) {
    def include(ops: List[Operation]): Operations = Operations(operations ++ ops)
  }

  case class BatchResult(digest: ADDigest, proof: SerializedAdProof, postDigest: Array[Byte])

  override type State = Operations
  override type Sut = BatchAVLProver[T, HF]

  val initialState = Operations(operations = List.empty[Operation])

  override def canCreateNewSut(newState: State,
                               initSuts: Traversable[State],
                               runningSuts: Traversable[Sut]): Boolean = true

  override def newSut(state: State): Sut = new BatchAVLProver[T, HF](keyLength = KL, valueLengthOpt = Some(VL))

  override def destroySut(sut: Sut): Unit = ()

  override def initialPreCondition(state: State): Boolean = state.operations.isEmpty

  override def genInitialState: Gen[State] = Gen.const(initialState)

  override def genCommand(state: State): Gen[Command] = PerformAndVerify(generateOperations(state))

  private def nextPositiveLong: Long = Random.nextInt(Int.MaxValue).toLong

  private def generateOperations(state: State): List[Operation] = {
    val appendsCommandsLength = Random.nextInt(MAXIMUM_GENERATED_OPERATIONS) + MINIMUM_OPERATIONS_LENGTH

    val keys = (0 until appendsCommandsLength).map { _ => ADKey @@ RandomBytes.randomBytes(KL) }.toList
    val removedKeys = state.operations.filter(_.isInstanceOf[Remove]).map(_.key).distinct
    val prevKeys = state.operations.map(_.key).distinct.filterNot(k1 => removedKeys.exists { k2 => k1.sameElements(k2) })
    val uniqueKeys = keys.filterNot(prevKeys.contains).distinct
    val updateKeys = Random.shuffle(prevKeys).take(safeDivide(prevKeys.length, UPDATE_FRACTION))
    val removeKeys = Random.shuffle(prevKeys).take(safeDivide(prevKeys.length, REMOVE_FRACTION))

    val appendCommands: List[Operation] = uniqueKeys.map { k => Insert(k, ADValue @@ Longs.toByteArray(nextPositiveLong)) }
    val updateCommands: List[Operation] = updateKeys.map { k => UpdateLongBy(k, nextPositiveLong) }
    val removeCommands: List[Operation] = removeKeys.map { k => Remove(k) }

    appendCommands ++ updateCommands ++ removeCommands
  }

  private def safeDivide(base: Int, fraction: Int): Int = if (base > fraction) base / fraction else 0

  case class PerformAndVerify(ops: List[Operation]) extends Command {
    override type Result = BatchResult

    override def run(sut: Sut): Result = {
      val digest = sut.digest
      ops.foreach(sut.performOneOperation)
      sut.checkTree(postProof = false)
      val proof = sut.generateProof()
      sut.checkTree(postProof = true)
      val postDigest = sut.digest
      BatchResult(digest, proof, postDigest)
    }

    override def nextState(state: Operations): Operations = state.include(ops)

    override def preCondition(state: Operations): Boolean = true

    override def postCondition(state: Operations, result: Try[Result]): Prop = {
      val check = result match {
        case Success(res) =>
          val verifier = new BatchAVLVerifier[T, HF](res.digest, res.proof, KL, Some(VL))
          ops.foreach(verifier.performOneOperation)
          verifier.digest.exists(_.sameElements(res.postDigest))
        case Failure(_) =>
          false
      }
      Prop.propBoolean(check)
    }
  }

}
