package scorex.crypto.hash

import ove.crypto.digest.Blake2b
import scorex.crypto.hash.CryptographicHash.Message

object Blake2b512 extends CryptographicHash {

  override val DigestSize: Int = 64

  override def hash(input: Message): Digest = Blake2b.Digest.newInstance(DigestSize).digest(input)
}