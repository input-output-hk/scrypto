package scorex.crypto.hash

object Groestl256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Groestl256
}