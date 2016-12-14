package scorex.crypto.hash

object Luffa512 extends FRHash64 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.Luffa512
}