package scrypto.hash

object Groestl256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Groestl256
}