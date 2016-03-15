package scorex.crypto.hash

object Fugue512 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Fugue512
}