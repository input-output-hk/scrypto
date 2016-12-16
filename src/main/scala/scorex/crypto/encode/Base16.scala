package scorex.crypto.encode

import scorex.utils.BytesHex

object Base16 {
  def encode(input: Array[Byte]): String = BytesHex.bytes2hex(input)

  def decode(input: String): Array[Byte] = BytesHex.hex2bytes(input)
}