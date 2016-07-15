package scorex.crypto.hash

object Whirlpool extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Whirlpool
}