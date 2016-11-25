package scrypto.hash

import ove.crypto.digest.Blake2b

object Blake2b512 extends CryptographicHash64 {

  override def hash(input: Message): Digest = Blake2b.Digest.newInstance(DigestSize).digest(input)
}