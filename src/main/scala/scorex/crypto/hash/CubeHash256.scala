package scorex.crypto.hash

import fr.cryptohash.Digest

object CubeHash256 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.CubeHash256
}