package scorex.crypto.hash

import fr.cryptohash.Digest

object Luffa512 extends FRHash {
  override protected val hf: Digest = new fr.cryptohash.Luffa512
}