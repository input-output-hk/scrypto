package scorex.crypto.hash

import fr.cryptohash.Digest

object Keccak256 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.Keccak256
}