package scrypto.hash

object CubeHash256 extends FRHash32 {
  override protected def hf: fr.cryptohash.Digest = new fr.cryptohash.CubeHash256
}