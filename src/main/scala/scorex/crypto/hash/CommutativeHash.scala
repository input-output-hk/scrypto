package scorex.crypto.hash

import scorex.crypto.hash.CryptographicHash.Message
import scorex.utils.ByteArray

class CommutativeHash[HashFn <: CryptographicHash](hf: HashFn) extends CryptographicHash {
  override val DigestSize: Int = hf.DigestSize

  override def hash(input: Message): Digest = hf.hash(input)

  def apply(x: Message, y:Message): Digest = hash(x, y)

  def hash(x: Message, y: Message): Digest = if (ByteArray.compare(x, y) > 0) hash(x ++ y) else hash(y ++ x)

}
