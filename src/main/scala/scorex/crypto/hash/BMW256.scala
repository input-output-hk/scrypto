package scorex.crypto.hash

import fr.cryptohash.{BMW256, Digest}

object BMW256 extends FRHash {
  override protected val hf: Digest = new BMW256
}