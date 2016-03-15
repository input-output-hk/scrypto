package scorex.crypto.hash

import scorex.crypto.hash.CryptographicHash.Message

trait FRHash extends CryptographicHash {
  protected def hf: fr.cryptohash.Digest
  override lazy val DigestSize: Int = hf.getDigestLength

  override def hash(input: Message): Digest = hf.digest(input)
}
