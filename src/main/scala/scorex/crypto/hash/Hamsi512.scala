package scorex.crypto.hash

object Hamsi512 extends FRHash64 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Hamsi512
}