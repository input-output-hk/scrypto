package scorex.crypto.hash

import org.bouncycastle.crypto.digests.SkeinDigest


object Skein512 extends BouncyCastleHash[Digest64] with CryptographicHash64 {

  override protected lazy val digestFn = new SkeinDigest(SkeinDigest.SKEIN_512, SkeinDigest.SKEIN_512)

  override def hash(input: Message): Digest64 = Digest64 @@ internalHash(input)
}




