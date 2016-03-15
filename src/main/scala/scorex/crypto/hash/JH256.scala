package scorex.crypto.hash

object JH256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.JH256
}