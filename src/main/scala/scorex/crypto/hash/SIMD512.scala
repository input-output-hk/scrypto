package scorex.crypto.hash

object SIMD512 extends FRHash64 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.SIMD512
}