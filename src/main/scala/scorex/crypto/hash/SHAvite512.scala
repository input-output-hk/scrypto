package scorex.crypto.hash

object SHAvite512 extends FRHash64 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.SHAvite512
}