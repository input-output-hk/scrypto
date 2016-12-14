package scorex.crypto.hash

trait FRHash extends CryptographicHash {
  override lazy val DigestSize: Int = hf.getDigestLength

  override def hash(input: Message): Digest = hf.digest(input)

  protected def hf: fr.cryptohash.Digest
}
