package scorex.crypto.hash

trait CryptographicHash32 extends CryptographicHash[Digest32] {

  override val DigestSize: Int = 32

}
