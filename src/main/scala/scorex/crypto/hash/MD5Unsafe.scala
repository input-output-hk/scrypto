package scorex.crypto.hash

import java.security.MessageDigest

class MD5Unsafe extends ThreadUnsafeHash {
  type Message = Array[Byte]
  type Digest = Array[Byte]

  val instance = MessageDigest.getInstance("MD5")

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
