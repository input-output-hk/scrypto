package scorex.crypto.hash

import org.bouncycastle.crypto.digests.KeccakDigest


trait Keccak extends BouncycastleHash {

  override protected lazy val digestFn = new KeccakDigest(DigestSize * 8)

}




