package scrypto.hash

import fr.cryptohash.BLAKE512

object Blake512 extends FRHash64 {
  override protected def hf: fr.cryptohash.Digest = new BLAKE512
}