package scorex.crypto.hash

object Hamsi256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Hamsi256
}