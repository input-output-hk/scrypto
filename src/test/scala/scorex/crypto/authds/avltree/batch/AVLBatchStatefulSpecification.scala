package scorex.crypto.authds.avltree.batch

import com.google.common.primitives.Longs
import org.scalacheck.Test.Parameters
import org.scalacheck.commands.Commands
import org.scalacheck.{Gen, Prop}
import org.scalatest.PropSpec
import scorex.crypto.authds.avltree.AVLKey
import scorex.crypto.hash.Blake2b256Unsafe
import scorex.utils.{Random => RandomBytes}

import scala.util.{Random, Try}

class AVLBatchStatefulSpecification extends PropSpec {

  private val params = Parameters.default
    .withMinSize(0)
    .withMaxSize(20)
    .withMinSuccessfulTests(100)
    .withWorkers(8)

  property("BatchAVLProver: prove and verify") {
    AVLCommands.property().check(params)
  }
}


object AVLCommands extends Commands {

  val KL = 32
  val VL = 2

  private val initialDigest = new BatchAVLProver(keyLength = KL, valueLengthOpt = Some(VL)).digest

  val MINIMUM_OPERATIONS_LENGTH = 10
  val MAXIMUM_GENERATED_OPERATIONS = 10
  val UPDATE_FRACTION = 2
  val REMOVE_FRACTION = 4

  type Hash = Blake2b256Unsafe

  case class Operations(operations: Vector[Operation])

  case class Stateful(prover: BatchAVLProver[Hash], verifier: BatchAVLVerifier[Hash])

  override type State = Operations
  override type Sut = Stateful

  val initialState = Operations(operations = Vector.empty[Operation])

  override def canCreateNewSut(newState: State,
                               initSuts: Traversable[State],
                               runningSuts: Traversable[Stateful]): Boolean = true

  override def newSut(state: State): Sut = {
    val initOp = Insert(RandomBytes.randomBytes(KL), Longs.toByteArray(Random.nextInt(Int.MaxValue).toLong))
    val prover = new BatchAVLProver[Hash](keyLength = KL, valueLengthOpt = Some(VL))
    prover.performOneOperation(initOp)
    val proof = prover.generateProof()
    val verifier = new BatchAVLVerifier[Hash](initialDigest, proof, KL, Some(VL))
    verifier.performOneOperation(initOp)
    Stateful(prover, verifier)
  }

  override def destroySut(sut: Sut): Unit = ()

  override def initialPreCondition(state: State): Boolean = state.operations.isEmpty

  override def genInitialState: Gen[State] = Gen.const(initialState)

  override def genCommand(state: State): Gen[Command] = Gen.frequency(2 -> generateOperations(state), 1 -> Check)

  private def generateOperations(state: State): Batch = {
    val appendsCommandsLength = Random.nextInt(MAXIMUM_GENERATED_OPERATIONS) + MINIMUM_OPERATIONS_LENGTH

    val keys: Vector[AVLKey] = (0 until appendsCommandsLength).map { _ => RandomBytes.randomBytes(KL) }.toVector
    val prevKeys = state.operations.map(_.key)
    //It seems too paranoid, just in case.
    val uniqueKeys = keys.filterNot(prevKeys.contains)
    val updateKeys = Random.shuffle(prevKeys).take(safeDivide(prevKeys.length, UPDATE_FRACTION))
    val removeKeys = Random.shuffle(prevKeys).take(safeDivide(prevKeys.length, REMOVE_FRACTION))

    val appendCommands: Vector[Operation] = uniqueKeys.map { k => Insert(k, Longs.toByteArray(Random.nextLong)) }
    val updateCommands: Vector[Operation] = updateKeys.map { k => UpdateLongBy(k, Random.nextInt(Int.MaxValue).toLong) }
    val removeCommands: Vector[Operation] = removeKeys.map { k => Remove(k) }
    val allCommands = Random.shuffle(appendCommands ++ updateCommands ++ removeCommands)

    Batch(allCommands)
  }

  private def safeDivide(base: Int, fraction: Int): Int = if (base > fraction) base / fraction else 0

  case class Batch(ops: Vector[Operation]) extends UnitCommand {

    override def run(sut: Stateful): Unit = {
      val opsToVerify = ops.filter { o => sut.prover.performOneOperation(o).isSuccess }
      sut.prover.generateProof()
      opsToVerify.foreach(sut.verifier.performOneOperation)
    }

    override def nextState(state: Operations): Operations = state.copy(state.operations ++ ops)

    override def preCondition(state: Operations): Boolean = true

    override def postCondition(state: Operations, success: Boolean): Prop = success
  }

  case object Check extends Command {
    override type Result = Boolean

    override def run(sut: Stateful): Boolean = {
      val proverDigest = sut.prover.digest
      val verifierDigest = sut.verifier.digest
      !proverDigest.sameElements(verifierDigest)
    }

    override def nextState(state: Operations): Operations = state

    override def preCondition(state: Operations): Boolean = true

    override def postCondition(state: Operations, result: Try[Boolean]): Prop =
      Prop.propBoolean(result.getOrElse(false))
  }
}
