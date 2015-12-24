package scorex.crypto.hash

import fr.cryptohash.Digest

object SIMD256 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.SIMD256
}