package scorex.crypto.hash

import org.bouncycastle.crypto.digests.KeccakDigest


trait Keccak[T <: Digest] extends BouncyCastleHash[T] {

  override protected lazy val digestFn = new KeccakDigest(DigestSize * 8)

}




