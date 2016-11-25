package scrypto.hash

object BMW256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.BMW256
}