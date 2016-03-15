package scorex.crypto.hash

object BMW256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.BMW256
}