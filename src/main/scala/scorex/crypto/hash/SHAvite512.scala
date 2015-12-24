package scorex.crypto.hash

import fr.cryptohash.Digest

object SHAvite512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.SHAvite512
}