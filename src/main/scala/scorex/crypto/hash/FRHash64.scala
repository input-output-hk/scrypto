package scorex.crypto.hash

trait FRHash64 extends CryptographicHash64 {

  override def hash(input: Message): Digest = hf.digest(input)

  protected def hf: fr.cryptohash.Digest
}
