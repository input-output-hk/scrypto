package scorex.utils

object Ints {
  /**
    * The number of bytes required to represent a primitive {@code int} value.
    *
    * <p><b>Java 8 users:</b> use {@link Integer# BYTES} instead.
    */
  val BYTES: Int = Integer.SIZE / java.lang.Byte.SIZE

  /**
    * Returns a big-endian representation of {@code value} in a 4-element byte array; equivalent to
    * {@code ByteBuffer.allocate(4).putInt(value).array()}. For example, the input value
    * {@code 0x12131415} would yield the byte array {@code {0x12, 0x13, 0x14, 0x15}}.
    */
  def toByteArray(value: Int): Array[Byte] = {
    Array[Byte]((value >> 24).toByte, (value >> 16).toByte, (value >> 8).toByte, value.toByte)
  }

  /**
    * Returns the {@code int} value whose big-endian representation is stored in the first 4 bytes of
    * {@code bytes}; equivalent to {@code ByteBuffer.wrap(bytes).getInt()}. For example, the input
    * byte array {@code {0x12, 0x13, 0x14, 0x15, 0x33}} would yield the {@code int} value
    * {@code 0x12131415}.
    *
    * @throws IllegalArgumentException if {@code bytes} has fewer than 4 elements
    */
  def fromByteArray(bytes: Array[Byte]): Int = {
    require(bytes.length >= BYTES, s"array too small: ${bytes.length} < $BYTES")
    fromBytes(bytes(0), bytes(1), bytes(2), bytes(3))
  }

  /**
    * Returns the {@code int} value whose byte representation is the given 4 bytes, in big-endian
    * order; equivalent to {@code Ints.fromByteArray(new byte[] {b1, b2, b3, b4})}.
    */
  def fromBytes(b1: Byte,
                b2: Byte,
                b3: Byte,
                b4: Byte): Int = {
    b1 << 24 | (b2 & 0xFF) << 16 | (b3 & 0xFF) << 8 | (b4 & 0xFF)
  }
}
