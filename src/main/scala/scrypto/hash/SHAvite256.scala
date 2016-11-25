package scrypto.crypto.hash

object SHAvite256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.SHAvite256
}