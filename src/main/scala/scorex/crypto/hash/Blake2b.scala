package scorex.crypto.hash

import org.bouncycastle.crypto.digests.Blake2bDigest


trait Blake2b[T <: Digest] extends BouncyCastleHash[T] {

  override protected lazy val digestFn = new Blake2bDigest(DigestSize * 8)

}



