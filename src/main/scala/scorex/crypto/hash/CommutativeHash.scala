package scorex.crypto.hash

import scorex.crypto.hash.CryptographicHash.Message

case class CommutativeHash[HashFn <: CryptographicHash](hf: HashFn) extends CryptographicHash {
  override val DigestSize: Int = hf.DigestSize

  override def hash(input: Message): Digest = hf.hash(input)

  def hash(x: Message, y: Message): Digest = if (scorex.crypto.compare(x, y) > 0) hash(x ++ y) else hash(y ++ x)

}
