package scorex.crypto.hash

import fr.cryptohash.Digest

object JH512 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.JH512
}