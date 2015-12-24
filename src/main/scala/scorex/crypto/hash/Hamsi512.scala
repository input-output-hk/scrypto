package scorex.crypto.hash

import fr.cryptohash.Digest

object Hamsi512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Hamsi512
}