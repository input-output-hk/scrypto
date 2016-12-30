package scorex.crypto.authds

import com.google.common.primitives.Longs
import scorex.crypto.TestingCommons
import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.avltree.AVLValue
import scorex.crypto.authds.legacy.treap.Constants.TreapValue
import scorex.crypto.hash.Sha256

import scala.util.{Failure, Success}


trait TwoPartyTests extends TestingCommons with UpdateF[Array[Byte]] {

  def profileTree(tree: TwoPartyDictionary[Array[Byte], Array[Byte], _ <: TwoPartyProof[Array[Byte], Array[Byte]]],
                  elements: Seq[Array[Byte]], inDigest: Label): Seq[Float] = {
    var digest = inDigest
    val (insertTime: Float, proofs) = time(elements.map(e => tree.modify(e, replaceLong(e)).get))
    val (verifyTime: Float, _) = time {
      proofs.foreach { p =>
        digest = p.verify(digest, replaceLong(p.key)).get
      }
    }
    val m: scala.collection.mutable.Map[Int, Float] =
      scala.collection.mutable.Map(0 -> 0, 1 -> 0, 2 -> 0, 3 -> 0, 4 -> 0, 5 -> 0)

    proofs.foreach { p =>
      p.proofSeq.foreach {
        case a: ProofLevel => m(0) = m(0) + 1
        case a: ProofRightLabel => m(1) = m(1) + 1
        case a: ProofLeftLabel => m(1) = m(1) + 1
        case a: ProofKey => m(2) = m(2) + 1
        case a: ProofNextLeafKey => m(2) = m(2) + 1
        case a: ProofValue => m(3) = m(3) + 1
        case a: ProofBalance => m(4) = m(4) + 1
        case a: ProofDirection => m(5) = m(5) + 1
      }
    }
    val pl: Float = proofs.length

    val proofSize = proofs.foldLeft(0) { (a, b) =>
      a + b.proofSeq.map(_.bytes.length).sum
    } / elements.length

    Seq(insertTime, verifyTime, proofSize, m(0) / pl, m(1) / pl, m(2) / pl, m(3) / pl, m(4) / pl, m(5) / pl)
  }

  def replaceLong(value: TreapValue): UpdateFunction = { oldOpt: Option[TreapValue] => Success(Some(value.take(8))) }

  def insertOnly(value: TreapValue): UpdateFunction = {
    case None => Success(Some(value))
    case _ => Failure(new Error("Don't update elements"))
  }

  def updateOnly(value: TreapValue): UpdateFunction = {
    case Some(v) => Success(Some(Sha256(v ++ value).take(value.length)))
    case _ => Failure(new Error("Don't insert elements"))
  }

  def rewrite(value: AVLValue): UpdateFunction = {
    oldOpt: Option[AVLValue] => Success(Some(value))
  }

  def append(value: TreapValue): UpdateFunction = { oldOpt: Option[TreapValue] =>
    Success(Some(oldOpt.map(_ ++ value).getOrElse(value)))
  }

  def transactionUpdate(amount: Long): UpdateFunction = (old: Option[TreapValue]) =>
    Success(Some(Longs.toByteArray(old.map(v => Longs.fromByteArray(v) + amount).getOrElse(amount))))
}
