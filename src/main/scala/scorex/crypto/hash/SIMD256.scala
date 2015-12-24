package scorex.crypto.hash

import fr.cryptohash.Digest

object SIMD256 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.SIMD256
}