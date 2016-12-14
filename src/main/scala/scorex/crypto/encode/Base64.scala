package scorex.crypto.encode

object Base64 {
  def encode(input: Array[Byte]): String = new String(java.util.Base64.getEncoder.encode(input))

  def decode(input: String): Array[Byte] = java.util.Base64.getDecoder.decode(input)

}