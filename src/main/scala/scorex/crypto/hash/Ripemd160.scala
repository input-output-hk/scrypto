package scorex.crypto.hash

import scorex.crypto.hash.CryptographicHash.{Digest, Message}

object Ripemd160 extends RIPEMD160J with CryptographicHash {
  override val DigestSize: Int = 160

  override def hash(input: Message): Digest = digest(input)
}
