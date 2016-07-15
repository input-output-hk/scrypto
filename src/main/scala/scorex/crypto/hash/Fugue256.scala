package scorex.crypto.hash

object Fugue256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Fugue256
}