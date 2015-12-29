package scorex.crypto.encode

import scorex.crypto._
import java.util.Base64

object Base64 {
  def encode(input: Array[Byte]): String = java.util.Base64.getEncoder.encode(input)

  def decode(input: String): Array[Byte] = hex2bytes(input)

}