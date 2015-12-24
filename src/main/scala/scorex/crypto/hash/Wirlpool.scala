package scorex.crypto.hash

import fr.cryptohash.Digest

object Wirlpool extends FRHash {
  override protected def hf: Digest = new fr.cryptohash.Whirlpool
}