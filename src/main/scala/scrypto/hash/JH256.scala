package scrypto.crypto.hash

object JH256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.JH256
}