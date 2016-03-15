package scorex.crypto.hash

object Groestl512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Groestl512
}