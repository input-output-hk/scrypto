package scorex.crypto.hash

import fr.cryptohash.Digest

object Fugue512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Fugue512
}