package scorex.crypto.hash

import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest

object Stribog512 extends BouncyCastleHash[Digest64] with CryptographicHash64 {

  override protected lazy val digestFn = new GOST3411_2012_512Digest

  override def hash(input: Message): Digest64 = Digest64 @@ internalHash(input)

  override def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Digest64 =
    Digest64 @@ internalPrefixedHash(prefix, inputs: _*)

}




