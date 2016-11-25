package scrypto.hash

object Groestl512 extends FRHash64 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Groestl512
}