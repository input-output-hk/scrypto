package scorex.crypto.hash

import fr.cryptohash.SHA512

object Sha512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new SHA512
}