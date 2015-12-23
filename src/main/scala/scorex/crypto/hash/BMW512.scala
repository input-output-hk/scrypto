package scorex.crypto.hash

import fr.cryptohash.{BMW512, Digest}

object BMW512 extends FRHash {
  override protected val hf: Digest = new BMW512
}