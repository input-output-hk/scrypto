package scorex.crypto.hash

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest

object Stribog256 extends BouncyCastleHash[Digest32] with CryptographicHash32 {

  override protected lazy val digestFn = new GOST3411_2012_256Digest

  override def hash(input: Message): Digest32 = Digest32 @@ internalHash(input)

  override def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Digest32 =
    Digest32 @@ internalPrefixedHash(prefix, inputs: _*)

}




