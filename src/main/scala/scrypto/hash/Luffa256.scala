package scrypto.crypto.hash

object Luffa256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Luffa256
}