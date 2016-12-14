package scorex.crypto.hash

object Whirlpool extends FRHash64 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Whirlpool
}