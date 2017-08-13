package scorex.crypto.hash

import org.bouncycastle.crypto.digests.WhirlpoolDigest


object Whirlpool extends BouncycastleHash with CryptographicHash64 {

  override protected lazy val digestFn = new WhirlpoolDigest

}
