package scorex.crypto.hash

import fr.cryptohash.{Groestl512, Digest}

object Groestl512 extends FRHash {
  override protected val hf: Digest = new Groestl512
}