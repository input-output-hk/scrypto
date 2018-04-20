package scorex.crypto.encode

import scala.util.Try

object Base64 extends BytesEncoder {

  override val Alphabet: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

  override def encode(input: Array[Byte]): String = new String(java.util.Base64.getEncoder.encode(input))

  override def decode(input: String): Try[Array[Byte]] = Try(java.util.Base64.getDecoder.decode(input))

}