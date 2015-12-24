package scorex.crypto.hash

import fr.cryptohash.Digest

object Skein256 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Skein256
}