package scorex.crypto.hash

import org.bouncycastle.crypto.digests.SkeinDigest

/**
  * In the Skein specification, that function is called under the full name "Skein-512-256".
  */
object Skein256 extends BouncyCastleHash[Digest32] with CryptographicHash32 {
  override protected lazy val digestFn = new SkeinDigest(SkeinDigest.SKEIN_512, SkeinDigest.SKEIN_256)

  override def hash(input: Message): Digest32 = Digest32 @@ internalHash(input)

  override def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Digest32 =
    Digest32 @@ internalPrefixedHash(prefix, inputs: _*)

}




