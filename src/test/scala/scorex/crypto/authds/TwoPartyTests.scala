package scorex.crypto.authds

import scorex.crypto.TestingCommons
import scorex.crypto.authds.wtree._

trait TwoPartyTests extends TestingCommons {

  def profileTree(tree: TwoPartyDictionary[Array[Byte], Array[Byte]],
                  elements: Seq[Array[Byte]], inDigest: Label): (Long, Long, Long) = {
    var digest = inDigest
    val (insertTime, proofs) = time(elements.map(e => tree.modify(e, append(e), true)))
    val (verifyTime, _) = time {
      proofs.foreach { p =>
        digest = p.verify(digest, append(p.key)).get
      }
    }
    val proofSize = proofs.foldLeft(Array[Byte]()) { (a, b) =>
      a ++ b.proofSeq.map(_.bytes).reduce(_ ++ _)
    }.length / elements.length
    (insertTime, verifyTime, proofSize)
  }

  def append(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => oldOpt.map(_ ++ value).getOrElse(value) }

}
