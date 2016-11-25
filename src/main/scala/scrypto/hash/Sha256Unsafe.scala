package scrypto.crypto.hash

import java.security.MessageDigest

/**
  * Thread-unsafe Sha256 alternative. Use with caution! Not for a multi-thread use!!!
  */
class Sha256Unsafe extends CryptographicHash32 with ThreadUnsafeHash {
  private val instance = MessageDigest.getInstance("SHA-256")

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