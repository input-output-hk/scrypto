package scorex.crypto.hash

import fr.cryptohash.Digest

object BMW256 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.BMW256
}