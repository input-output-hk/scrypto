package scorex.crypto.hash

import fr.cryptohash.Digest

object Groestl512 extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Groestl512
}