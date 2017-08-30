package scorex.crypto.hash

trait CryptographicHash64 extends CryptographicHash[Digest64] {

  override val DigestSize: Int = 64

}
