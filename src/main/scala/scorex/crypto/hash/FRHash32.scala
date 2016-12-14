package scorex.crypto.hash

trait FRHash32 extends CryptographicHash32 {

  override def hash(input: Message): Digest = hf.digest(input)

  protected def hf: fr.cryptohash.Digest
}
