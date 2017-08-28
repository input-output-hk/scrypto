package scorex.crypto.hash

trait CryptographicHash32 extends CryptographicHash {

  override val DigestSize: Int = 32

}
