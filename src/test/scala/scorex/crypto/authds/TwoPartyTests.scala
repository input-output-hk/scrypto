package scorex.crypto.authds

import scorex.crypto.TestingCommons
import scorex.crypto.authds.wtree._

trait TwoPartyTests extends TestingCommons {

  def profileTree(tree: TwoPartyDictionary[Array[Byte], Array[Byte]],
                  elements: Seq[Array[Byte]], inDigest: Label): Seq[Float] = {
    var digest = inDigest
    val (insertTime, proofs) = time(elements.map(e => tree.modify(e, append(e), true)))
    val (verifyTime, _) = time {
      proofs.foreach { p =>
        digest = p.verify(digest, append(p.key)).get
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

    val proofSize = proofs.foldLeft(Array[Byte]()) { (a, b) =>
      a ++ b.proofSeq.map(_.bytes).reduce(_ ++ _)
    }.length / elements.length
    Seq(insertTime, verifyTime, proofSize, m(0) / pl, m(1) / pl, m(2) / pl, m(3) / pl, m(4) / pl, m(5) / pl)
  }

  def append(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => oldOpt.map(_ ++ value).getOrElse(value) }

}
