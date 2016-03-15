package scorex.crypto.hash

object Keccak512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Keccak512
}