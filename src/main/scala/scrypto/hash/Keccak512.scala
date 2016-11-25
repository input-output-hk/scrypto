package scrypto.hash

object Keccak512 extends FRHash64 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Keccak512
}