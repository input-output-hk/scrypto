package scorex.crypto.hash

import fr.cryptohash.Digest

object Skein256 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.Skein256
}