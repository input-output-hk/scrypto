package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.util.Try


case class SLProofSeq(height: Int, proofs: Seq[ProofToRecalculate]) {
  type Digest = CryptographicHash#Digest

  def check[HF <: CommutativeHash[_]](rootHash: Digest, newRootHash: Digest)(implicit hashFunction: HF): Boolean = {
    def loop(rProofs: Seq[ProofToRecalculate], curRootHash: Digest, curHeight: Int): Boolean = rProofs.headOption match {
      case Some(proofToRecalculate) =>
        if (proofToRecalculate.proof.check(curRootHash)) {
          val (newRH, newLev) = ExtendedSLProof.recalculateProof(proofToRecalculate, curHeight)
          loop(rProofs.tail, newRH, newLev)
        } else false
      case None => curRootHash sameElements newRootHash
    }
    loop(proofs, rootHash, height)
  }

  lazy val bytes: Array[Byte] = {
    val hb = Ints.toByteArray(height)
    val pb = proofs.foldLeft(Array[Byte]()) { (a, b) =>
      val proofEBytes = b.newEl.bytes
      val proofPBytes = b.proof.bytes
      Ints.toByteArray(proofEBytes.length) ++ Ints.toByteArray(proofPBytes.length) ++ proofEBytes ++ proofPBytes
    }
    hb ++ pb
  }

}

object SLProofSeq {
  def parseBytes(bytes: Array[Byte]): Try[SLProofSeq] = Try {
    def parseProofs(b: Array[Byte]): Seq[ProofToRecalculate] = if (b.isEmpty) {
      Seq()
    } else {
      val elLength = Ints.fromByteArray(b.slice(0, 4))
      val pLength = Ints.fromByteArray(b.slice(4, 8))
      val e = SLElement.parseBytes(b.slice(8, 8 + elLength)).get
      val p = ExtendedSLProof.parseBytes(b.slice(8 + elLength, 8 + elLength + pLength)).get
      ProofToRecalculate(e, p) +: parseProofs(b.slice(8 + elLength + pLength, b.length))
    }
    val height = Ints.fromByteArray(bytes.slice(0, 4))
    val proofs = parseProofs(bytes.slice(4, bytes.length))
    SLProofSeq(height, proofs)
  }
}

