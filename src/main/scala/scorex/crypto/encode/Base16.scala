package scorex.crypto.encode

import org.bouncycastle.util.encoders.Hex

import scala.util.Try

object Base16 extends BytesEncoder {

  override val Alphabet: String = "0123456789abcdefABCDEF"

  def encode(input: Array[Byte]): String = Hex.toHexString(input)

  def decode(input: String): Try[Array[Byte]] = Try(Hex.decode(input))

}