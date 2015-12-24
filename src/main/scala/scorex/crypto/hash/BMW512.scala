package scorex.crypto.hash

import fr.cryptohash.Digest

object BMW512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.BMW512
}