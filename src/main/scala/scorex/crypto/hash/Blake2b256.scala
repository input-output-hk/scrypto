package scorex.crypto.hash

import ove.crypto.digest.Blake2b

object Blake2b256 extends CryptographicHash32 {
  override def hash(input: Message): Digest = Blake2b.Digest.newInstance(DigestSize).digest(input)
}

/**
  * Thread-unsafe Blake2b alternative. Use with caution! Not for a multi-thread use!!!
  */
object Blake2b256Unsafe extends CryptographicHash32 {
  private val instance = Blake2b.Digest.newInstance(DigestSize)
  override def hash(input: Message): Digest = instance.digest(input)
}