package scorex.crypto.hash

import fr.cryptohash.Digest

object JH512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.JH512
}