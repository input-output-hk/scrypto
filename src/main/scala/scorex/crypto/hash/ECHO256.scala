package scorex.crypto.hash

import fr.cryptohash.Digest

object ECHO256 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.ECHO256
}