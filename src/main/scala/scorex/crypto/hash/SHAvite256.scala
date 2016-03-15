package scorex.crypto.hash

object SHAvite256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.SHAvite256
}