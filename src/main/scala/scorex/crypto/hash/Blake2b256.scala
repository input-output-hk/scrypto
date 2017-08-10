package scorex.crypto.hash

import org.bouncycastle.crypto.digests.Blake2bDigest


trait Blake2b extends CryptographicHash {

  private lazy val digestFn = new Blake2bDigest(DigestSize*8)

  override def hash(input: Message): Digest = synchronized {
    digestFn.update(input, 0, input.length)
    val res = new Array[Byte](DigestSize)
    digestFn.doFinal(res, 0)
    res
  }
}


object Blake2b256 extends Blake2b with CryptographicHash32

object Blake2b512 extends Blake2b with CryptographicHash64