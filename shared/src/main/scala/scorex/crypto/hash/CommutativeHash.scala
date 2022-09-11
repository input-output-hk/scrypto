package scorex.crypto.hash

import scorex.utils.ByteArray

import scala.util.Try

class CommutativeHash[D <: Digest](hf: CryptographicHash[D]) extends CryptographicHash[D] {
  override val DigestSize: Int = hf.DigestSize

  def apply(x: Message, y: Message): D = hash(x, y)

  def hash(x: Message, y: Message): D = hash(commutativeBytes(x, y))

  override def hash(input: Message): D = hf.hash(input)

  def prefixedHash(prefix: Byte, x: Message, y: Message): D = prefixedHash(prefix, commutativeBytes(x, y))

  private def commutativeBytes(x: Message, y: Message): Message = if (ByteArray.compare(x, y) > 0) x ++ y else y ++ x

  override def byteArrayToDigest(bytes: Array[Byte]): Try[D] = hf.byteArrayToDigest(bytes)
}
