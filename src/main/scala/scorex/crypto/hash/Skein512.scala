package scorex.crypto.hash

object Skein512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Skein512
}