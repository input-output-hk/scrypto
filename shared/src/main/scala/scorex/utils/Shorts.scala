package scorex.utils

object Shorts {
  /**
    * Returns a big-endian representation of {@code value} in a 2-element byte array; equivalent to
    * {@code ByteBuffer.allocate(2).putShort(value).array()}. For example, the input value {@code
    * (short) 0x1234} would yield the byte array {@code {0x12, 0x34}}.
    */
  def toByteArray(value: Short): Array[Byte] = {
    Array[Byte]((value >> 8).toByte, value.toByte)
  }
}
