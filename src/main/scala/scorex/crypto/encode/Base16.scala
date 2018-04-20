package scorex.crypto.encode

import scala.util.Try

object Base16 extends BytesEncoder {

  override val Alphabet: String = "0123456789abcdefABCDEF"

  def encode(input: Array[Byte]): String = bytes2hex(input, None)

  def decode(input: String): Try[Array[Byte]] = Try(hex2bytes(input.toLowerCase()))

  private def bytes2hex(bytes: Array[Byte], sep: Option[String]): String =
    bytes.map("%02x".format(_)).mkString(sep.getOrElse(""))

  private def hex2bytes(hex: String): Array[Byte] = {
    hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
  }
}