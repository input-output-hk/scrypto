package scrypto.hash

object Skein256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Skein256
}