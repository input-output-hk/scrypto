package scorex.crypto.hash

import org.bouncycastle.crypto.digests.Blake2bDigest

/**
  * Thread-unsafe Blake2b alternative. Use with caution! Not for a multi-thread use!!!
  */
class Blake2b256Unsafe extends CryptographicHash32 with ThreadUnsafeHash {
  private val digestFn = new Blake2bDigest(DigestSize * 8)

  override def hash(input: Message): Digest = {
    digestFn.update(input, 0, input.length)
    val res = new Array[Byte](DigestSize)
    digestFn.doFinal(res, 0)
    res
  }

  override def hash(inputs: Message*): Digest = {
    inputs.foreach(i => digestFn.update(i, 0, i.length))
    val res = new Array[Byte](DigestSize)
    digestFn.doFinal(res, 0)
    res
  }

  override def prefixedHash(prefix: Byte, inputs: Message*): Digest = {
    digestFn.update(prefix)
    hash(inputs:_*)
  }
}