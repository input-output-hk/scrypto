package scorex.crypto.hash

import fr.cryptohash.BLAKE512

object Blake512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new BLAKE512
}