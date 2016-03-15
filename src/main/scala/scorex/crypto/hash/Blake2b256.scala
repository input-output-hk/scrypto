package scorex.crypto.hash

import ove.crypto.digest.Blake2b
import scorex.crypto.hash.CryptographicHash.Message

object Blake2b256 extends CryptographicHash {
  override val DigestSize: Int = 32

  override def hash(input: Message): Digest = Blake2b.Digest.newInstance(DigestSize).digest(input)
}