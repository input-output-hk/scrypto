package scorex.crypto.hash

import org.bouncycastle.crypto.digests.SkeinDigest

/**
  * In the Skein specification, that function is called under the full name "Skein-512-256".
  */
object Skein256 extends BouncycastleHash with CryptographicHash32 {

  override protected lazy val digestFn = new SkeinDigest(SkeinDigest.SKEIN_512, SkeinDigest.SKEIN_256)
}




