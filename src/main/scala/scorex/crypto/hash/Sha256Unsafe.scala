package scorex.crypto.hash

import java.security.MessageDigest

/**
  * Thread-unsafe Sha256 alternative. Use with caution! Not for a multi-thread use!!!
  */
class Sha256Unsafe extends CryptographicHash32 with ThreadUnsafeHash[Digest32] {
  private val instance = MessageDigest.getInstance("SHA-256")

  override def hash(input: Message): Digest32 = Digest32 @@ instance.digest(input)

  override def hash(inputs: Message*): Digest32 = {
    inputs.foreach(i => instance.update(i))
    val digest = instance.digest()
    instance.reset()
    Digest32 @@ digest
  }

  override def prefixedHash(prefix: Byte, inputs: Message*): Digest32 = {
    instance.update(prefix)
    inputs.foreach(i => instance.update(i))
    val digest = instance.digest()
    instance.reset()
    Digest32 @@ digest
  }
}