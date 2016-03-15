package scorex.crypto.hash

object Skein256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Skein256
}