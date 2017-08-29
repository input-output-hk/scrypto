package scorex.crypto.hash

import scorex.utils.ByteArray

class CommutativeHash[T <: Digest](hf: CryptographicHash[T]) extends CryptographicHash[T] {
  override val DigestSize: Int = hf.DigestSize

  def apply(x: Message, y: Message): T = hash(x, y)

  def hash(x: Message, y: Message): T = hash(commutativeBytes(x, y))

  override def hash(input: Message): T = hf.hash(input)

  override def prefixedHash(prefix: Byte, x: Message, y: Message): T = prefixedHash(prefix, commutativeBytes(x, y))

  private def commutativeBytes(x: Message, y: Message): Message = if (ByteArray.compare(x, y) > 0) x ++ y else y ++ x
}
