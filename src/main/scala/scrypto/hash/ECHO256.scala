package scrypto.crypto.hash

object ECHO256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.ECHO256
}