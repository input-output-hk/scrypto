package scorex.crypto.hash

import org.bouncycastle.crypto.digests.KeccakDigest


trait Keccak extends CryptographicHash {

  private lazy val digestFn = new KeccakDigest(DigestSize*8)

  override def hash(input: Message): Digest = synchronized {
    digestFn.update(input, 0, input.length)
    val res = new Array[Byte](DigestSize)
    digestFn.doFinal(res, 0)
    res
  }
}


object Keccak256 extends Keccak with CryptographicHash32

object Keccak512 extends Keccak with CryptographicHash64