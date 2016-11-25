package scrypto.hash

import ove.crypto.digest.Blake2b

/**
  * Thread-unsafe Blake2b alternative. Use with caution! Not for a multi-thread use!!!
  */
class Blake2b256Unsafe extends CryptographicHash32 with ThreadUnsafeHash {
  private val instance = Blake2b.Digest.newInstance(DigestSize)

  override def hash(input: Message): Digest = instance.digest(input)

  override def hash(inputs: Message*): Digest = {
    inputs.foreach(i => instance.update(i))
    val digest = instance.digest()
    instance.reset()
    digest
  }

  override def prefixedHash(prefix: Byte, inputs: Message*): Digest = {
    instance.update(prefix)
    inputs.foreach(i => instance.update(i))
    val digest = instance.digest()
    instance.reset()
    digest
  }
}