package scorex.crypto.hash

import fr.cryptohash.Digest

object JH256 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.JH256
}