package scorex.crypto.hash

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest

object Stribog256 extends BouncycastleHash with CryptographicHash32 {

  override protected lazy val digestFn = new GOST3411_2012_256Digest
}




