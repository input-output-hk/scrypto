package scorex.crypto.hash

import fr.cryptohash.Digest

object Keccak256 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Keccak256
}