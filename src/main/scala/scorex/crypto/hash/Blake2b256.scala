package scorex.crypto.hash

import org.bouncycastle.crypto.digests.Blake2bDigest


trait Blake2b extends BouncycastleHash {

  override protected lazy val digestFn = new Blake2bDigest(DigestSize * 8)

}


object Blake2b256 extends Blake2b with CryptographicHash32

object Blake2b512 extends Blake2b with CryptographicHash64