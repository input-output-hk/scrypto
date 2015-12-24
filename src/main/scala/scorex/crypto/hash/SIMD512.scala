package scorex.crypto.hash

import fr.cryptohash.Digest

object SIMD512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.SIMD512
}