package scorex.crypto.hash

import org.bouncycastle.crypto.digests.KeccakDigest

trait Keccak[D <: Digest] extends BouncyCastleHash[D] {
  override protected lazy val digestFn = new KeccakDigest(DigestSize * 8)
}




