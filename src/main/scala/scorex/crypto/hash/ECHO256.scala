package scorex.crypto.hash

object ECHO256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.ECHO256
}