package scorex.crypto.hash

import org.bouncycastle.crypto.digests.KeccakDigest


trait Keccak[T <: Digest] extends BouncycastleHash[T] {

  override protected lazy val digestFn = new KeccakDigest(DigestSize * 8)

}




