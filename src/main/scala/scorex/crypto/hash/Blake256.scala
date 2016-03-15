package scorex.crypto.hash

import fr.cryptohash.BLAKE256

object Blake256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new BLAKE256
}