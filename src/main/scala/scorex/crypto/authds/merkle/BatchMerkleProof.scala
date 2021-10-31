package scorex.crypto.authds.merkle

import scorex.crypto.authds.{LeafData, Side}
import scorex.crypto.hash.{CryptographicHash, Digest}
import scorex.util.ScorexEncoding

import scala.language.postfixOps

case class BatchMerkleProof[D <: Digest](indexes: Seq[(Int, Digest)], proofs: Seq[Digest])
                                        (implicit val hf: CryptographicHash[D]) extends ScorexEncoding {

  def valid(expectedRootHash: Digest, hashes: Seq[Leaf[D]]): Boolean = {

    def loop(a: Seq[Int], e: Seq[(Int, Digest)], m: Seq[Digest]): Seq[Digest] = {

      val b = a
        .map(i => {
          if (i % 2 == 0) {
            (i, i + 1)
          } else {
            (i - 1, i)
          }
        })

      assert(e.length == b.length);

      var a_new: Seq[Int] = Seq.empty
      var e_new: Seq[Digest] = Seq.empty
      var m_new = m

      var i = 0

      while (i < b.size) {

        if (b.size > 1 && b.apply(i) == b.apply(i + 1)) {
          e_new = e_new :+ hf.getValue(hf.hash(e.apply(i)._2 ++ e.apply(i + 1)._2))
          i += 2
        } else {
          e_new = e_new :+ hf.getValue(hf.hash(e.apply(i)._2 ++ m.head))
          m_new = m_new.tail
          i += 1
        }
      }

      a_new = b.distinct.map(_._1 / 2)

      if (m_new.nonEmpty) {
        e_new = loop(a_new, a_new zip e_new, m_new)
      }
      assert(e_new.size == 1)
      e_new
    }

    val e = indexes sortBy(_._1)

    loop(indexes.map(_._1), e, proofs).head.sameElements(expectedRootHash)

  }
}