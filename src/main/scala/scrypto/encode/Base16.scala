package scrypto.encode

import scrypto.utils.BytesHex

object Base16 {
  def encode(input: Array[Byte]): String = BytesHex.bytes2hex(input)

  def decode(input: String): Array[Byte] = BytesHex.hex2bytes(input)
}