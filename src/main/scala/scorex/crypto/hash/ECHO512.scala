package scorex.crypto.hash

import fr.cryptohash.Digest

object ECHO512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.ECHO512
}