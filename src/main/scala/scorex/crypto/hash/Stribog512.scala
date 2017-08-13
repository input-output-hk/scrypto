package scorex.crypto.hash

import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest

object Stribog512 extends BouncycastleHash with CryptographicHash64 {

  override protected lazy val digestFn = new GOST3411_2012_512Digest

}




