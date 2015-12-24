package scorex.crypto.hash

import fr.cryptohash.Digest

object SHAvite256 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.SHAvite256
}