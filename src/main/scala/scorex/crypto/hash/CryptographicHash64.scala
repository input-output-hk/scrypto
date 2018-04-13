package scorex.crypto.hash

import scala.util.Try

trait CryptographicHash64 extends CryptographicHash[Digest64] {

  override val DigestSize: Int = 64

  override def byteArrayToDigest(bytes: Array[Byte]): Try[Digest64] = Try {
    require(bytes.lengthCompare(DigestSize) == 0, "Incorrect digest size")
    Digest64 @@ bytes
  }

}
