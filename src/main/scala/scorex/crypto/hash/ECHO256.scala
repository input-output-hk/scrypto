package scorex.crypto.hash

import fr.cryptohash.Digest

object ECHO256 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.ECHO256
}