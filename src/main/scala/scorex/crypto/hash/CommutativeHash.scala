package scorex.crypto.hash

import scorex.utils.ByteArray

class CommutativeHash[HashFn <: CryptographicHash](hf: HashFn) extends CryptographicHash {
  override val DigestSize: Int = hf.DigestSize

  override def hash(input: Message): Digest = hf.hash(input)

  def apply(x: Message, y: Message): Digest = hash(x, y)

  def hash(x: Message, y: Message): Digest = hash(commutativeBytes(x, y))

  def prefixedHash(prefix: Byte, x: Message, y: Message): Array[Byte] = hash(prefix +: commutativeBytes(x, y))

  def prefixedHash(prefix: Byte, x: Message): Array[Byte] = hash(prefix +: x)

  private def commutativeBytes(x: Message, y: Message): Message = if (ByteArray.compare(x, y) > 0) x ++ y else y ++ x
}
