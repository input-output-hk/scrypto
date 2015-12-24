package scorex.crypto.hash

import fr.cryptohash.Digest

object Fugue256 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Fugue256
}