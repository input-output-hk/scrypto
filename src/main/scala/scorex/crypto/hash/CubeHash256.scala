package scorex.crypto.hash

import fr.cryptohash.Digest

object CubeHash256 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.CubeHash256
}