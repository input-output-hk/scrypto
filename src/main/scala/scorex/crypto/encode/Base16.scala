package scorex.crypto.encode

import scorex.crypto._

object Base16 {
  def encode(input: Array[Byte]): String = bytes2hex(input)

  def decode(input: String): Array[Byte] = hex2bytes(input)

}