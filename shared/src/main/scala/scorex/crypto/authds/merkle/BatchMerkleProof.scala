package scorex.crypto.authds.merkle

import scorex.crypto.authds.Side
import scorex.crypto.authds.merkle.MerkleProof.LeftSide
import scorex.crypto.authds.merkle.MerkleTree.InternalNodePrefix
import scorex.crypto.hash.{CryptographicHash, Digest}
import scorex.util.ScorexEncoding

import java.util
import scala.language.postfixOps

  /**
    * Implementation is based on Compact Merkle Multiproofs by Lum Ramabaja
    * Retrieved from https://deepai.org/publication/compact-merkle-multiproofs
    *
    * @param indices - leaf indices used to build the proof
    * @param proofs - hash and side of nodes in the proof
    */
case class BatchMerkleProof[D <: Digest](indices: Seq[(Int, Digest)], proofs: Seq[(Digest, Side)])
                                        (implicit val hf: CryptographicHash[D]) extends ScorexEncoding {

  /**
    * Validate BatchMerkleProof against an expected root hash
    *
    * @param expectedRootHash - BatchMerkleProof should evaluate to this hash
    * @return true or false (Boolean)
    */
  def valid(expectedRootHash: Digest): Boolean = {

    /**
      * Recursive function to validate the multiproof
      *
      * @param a - leaf indices
      * @param e - sorted pairs of (index, hash) of the leaves
      * @param m - hashes of the multiproof
      * @return true or false (Boolean)
      */
    def loop(a: Seq[Int], e: Seq[(Int, Digest)], m: Seq[(Digest, Side)]): Seq[Digest] = {

      // For each of the indices in A, take the index of its immediate neighbor
      // Store the given element index and the neighboring index as a pair of indices
      val b = a
        .map(i => {
          if (i % 2 == 0) {
            (i, i + 1)
          } else {
            (i - 1, i)
          }
        })

      // B will always have the same size as E
      assert(e.size == b.size)

      var a_new: Seq[Int] = Seq.empty
      var e_new: Seq[Digest] = Seq.empty
      var m_new = m

      var i = 0

      // assign generated hashes to a new E that will be used for the next iteration
      while (i < b.size) {

        // check for duplicate index pairs inside b
        if (b.size > 1 && b.lift(i) == b.lift(i + 1)) {

          // hash the corresponding values inside E with one another
          e_new = e_new :+ hf.prefixedHash(InternalNodePrefix, e.apply(i)._2 ++ e.apply(i + 1)._2)
          i += 2
        } else {

          // hash the corresponding value inside E with the first hash inside M, taking note of the side
          if (m_new.head._2 == LeftSide) {
            e_new = e_new :+ hf.prefixedHash(InternalNodePrefix, m_new.head._1 ++ e.apply(i)._2)
          } else {
            e_new = e_new :+ hf.prefixedHash(InternalNodePrefix, e.apply(i)._2 ++ m_new.head._1)
          }

          // remove the used value from m
          m_new = m_new.drop(1)
          i += 1
        }
      }

      //  Take all the even numbers from B_pruned, and divide them by two
      a_new = b.distinct.map(_._1 / 2)

      // Repeat until the root of the tree is reached (M has no more elements)
      if ((m_new.nonEmpty || e_new.size > 1) && a_new.nonEmpty) {
        e_new = loop(a_new, a_new zip e_new, m_new)
      }
      e_new
    }

    val e = indices sortBy(_._1)
    loop(indices.map(_._1), e, proofs) match {
      case root: Seq[Digest] if root.size == 1 => root.head.sameElements(expectedRootHash)
      case _ => false
    }
  }

    override def equals(obj: Any): Boolean = obj match {
      case that: BatchMerkleProof[D] =>
        if (this.indices.size != that.indices.size ||
          this.proofs.size != that.proofs.size) {
          return false
        }
        for (i <- this.indices.indices) {
          if (this.indices.apply(i)._1 != that.indices.apply(i)._1 ||
            !util.Arrays.equals(this.indices.apply(i)._2, that.indices.apply(i)._2)) {
            return false
          }
        }
        for (i <- this.proofs.indices) {
          if (this.proofs.apply(i)._2 != that.proofs.apply(i)._2 ||
            !util.Arrays.equals(this.proofs.apply(i)._1, that.proofs.apply(i)._1)) {
            return false
          }
        }
        true
      case _ => false
    }
}