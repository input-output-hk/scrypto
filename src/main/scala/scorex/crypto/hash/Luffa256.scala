package scorex.crypto.hash

object Luffa256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Luffa256
}