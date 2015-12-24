package scorex.crypto.hash

import fr.cryptohash.{Digest, BLAKE512}

object Blake512 extends FRHash {
  override protected def hf: Digest = new BLAKE512
}