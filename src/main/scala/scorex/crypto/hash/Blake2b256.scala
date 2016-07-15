package scorex.crypto.hash

import ove.crypto.digest.Blake2b

object Blake2b256 extends CryptographicHash32 {

  override def hash(input: Message): Digest = Blake2b.Digest.newInstance(DigestSize).digest(input)
}