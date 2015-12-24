package scorex.crypto.hash

import fr.cryptohash.Digest

object BMW512 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.BMW512
}