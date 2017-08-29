package scorex.crypto.hash

import org.bouncycastle.crypto.digests.WhirlpoolDigest


object Whirlpool extends BouncyCastleHash[Digest64] with CryptographicHash64 {

  override protected lazy val digestFn = new WhirlpoolDigest

  override def hash(input: Message): Digest64 = Digest64 @@ internalHash(input)
}
