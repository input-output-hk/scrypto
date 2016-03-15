package scorex.crypto.hash

object BMW512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.BMW512
}