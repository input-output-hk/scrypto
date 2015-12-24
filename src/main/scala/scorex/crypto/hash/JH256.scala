package scorex.crypto.hash

import fr.cryptohash.Digest

object JH256 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.JH256
}