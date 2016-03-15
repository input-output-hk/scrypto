package scorex.crypto.hash

object SIMD512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.SIMD512
}