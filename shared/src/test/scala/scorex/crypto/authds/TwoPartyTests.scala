package scorex.crypto.authds

import scorex.utils.{Longs, Logger}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.avltree.batch.{Modification, Update}
import scorex.crypto.hash.Digest

import scala.util.Success


trait TwoPartyTests extends TestingCommons {

  implicit val loggerInTests: Logger = Logger.Default

  def genUpd(key: ADKey) = Update(key, ADValue @@ key.take(8))

  def profileTree(tree: TwoPartyDictionary, elements: Seq[ADKey], inDigest: ADDigest): Seq[Float] = {
    var digest = inDigest
    val (insertTime: Float, proofs) = time(elements.map(e => tree.run(genUpd(e)).get))
    val (verifyTime: Float, _) = time {
      proofs.foreach { p =>
        digest = p.verify(digest, genUpd(p.key).updateFn).get
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

  case class Append(key: ADKey, value: ADValue) extends Modification {
    override def updateFn: UpdateFunction = {
      (oldOpt: Option[ADValue]) => Success(Some(ADValue @@ oldOpt.map(_ ++ value).getOrElse(value)))
    }: UpdateFunction
  }

  case class TransactionUpdate(key: ADKey, amount: Long) extends Modification {
    override def updateFn: UpdateFunction = {
      (oldOpt: Option[ADValue]) =>
        Success(Some(ADValue @@ Longs.toByteArray(oldOpt.map(v => Longs.fromByteArray(v) + amount).getOrElse(amount))))
    }: UpdateFunction
  }

}
