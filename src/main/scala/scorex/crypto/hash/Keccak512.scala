package scorex.crypto.hash

import fr.cryptohash.Digest

object Keccak512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Keccak512
}