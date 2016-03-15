package scorex.crypto.hash

object Keccak256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Keccak256
}