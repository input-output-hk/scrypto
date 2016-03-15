package scorex.crypto.hash

object CubeHash256 extends FRHash {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.CubeHash256
}