package scorex.crypto.hash

import fr.cryptohash.Digest

object Hamsi256 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Hamsi256
}