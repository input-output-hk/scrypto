package scrypto.crypto.hash

object Keccak256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Keccak256
}