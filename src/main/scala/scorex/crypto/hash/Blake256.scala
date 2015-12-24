package scorex.crypto.hash

import fr.cryptohash.{BLAKE256, Digest}

object Blake256 extends FRHash {
  override protected val hf: Digest = new BLAKE256
}