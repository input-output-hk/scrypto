package scorex.crypto.hash

object ECHO512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.ECHO512
}