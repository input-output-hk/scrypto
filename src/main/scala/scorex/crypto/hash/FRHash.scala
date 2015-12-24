package scorex.crypto.hash

import fr.cryptohash.Digest
import scorex.crypto.hash.CryptographicHash.Message

trait FRHash extends CryptographicHash {
  protected def hf: Digest
  override lazy val DigestSize: Int = hf.getDigestLength

  override def hash(input: Message): CryptographicHash.Digest = hf.digest(input)
}
