package scorex.utils

/** Operations with long values. The implementation is based on com.google.common.primitives.Longs. */
object Longs {
  /**
    * The number of bytes required to represent a primitive {@code long} value.
    *
    * <p><b>Java 8 users:</b> use {@link Long# BYTES} instead.
    */
  val BYTES: Int = java.lang.Long.SIZE / java.lang.Byte.SIZE

  /**
    * Returns a big-endian representation of {@code value} in an 8-element byte array; equivalent to
    * {@code ByteBuffer.allocate(8).putLong(value).array()}. For example, the input value
    * {@code 0x1213141516171819L} would yield the byte array {@code {0x12, 0x13, 0x14, 0x15, 0x16,
   * 0x17, 0x18, 0x19}}.
    */
  def toByteArray(value: Long): Array[Byte] = {
    // Note that this code needs to stay compatible with GWT, which has known
    // bugs when narrowing byte casts of long values occur.
    var v = value
    val result = new Array[Byte](8)
    var i = 7
    while (i >= 0) {
      result(i) = (v & 0xffL).toByte
      v >>= 8
      i -= 1
    }
    result
  }

  /**
    * Returns the {@code long} value whose big-endian representation is stored in the first 8 bytes
    * of {@code bytes}; equivalent to {@code ByteBuffer.wrap(bytes).getLong()}. For example, the
    * input byte array {@code {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}} would yield the
    * {@code long} value {@code 0x1213141516171819L}.
    *
    * @throws IllegalArgumentException if {@code bytes} has fewer than 8 elements
    */
  def fromByteArray(bytes: Array[Byte]): Long = {
    require(bytes.length >= BYTES, s"array too small: ${bytes.length} < $BYTES")
    fromBytes(bytes(0), bytes(1), bytes(2), bytes(3), bytes(4), bytes(5), bytes(6), bytes(7))
  }

  /**
    * Returns the {@code long} value whose byte representation is the given 8 bytes, in big-endian
    * order; equivalent to {@code Longs.fromByteArray(new byte[] {b1, b2, b3, b4, b5, b6, b7, b8})}.
    *
    * @since 7.0
    */
  def fromBytes(b1: Byte,
                b2: Byte,
                b3: Byte,
                b4: Byte,
                b5: Byte,
                b6: Byte,
                b7: Byte,
                b8: Byte): Long = {
    (b1 & 0xFFL) << 56 | (b2 & 0xFFL) << 48 | (b3 & 0xFFL) << 40 | (b4 & 0xFFL) << 32 | (b5 & 0xFFL) << 24 | (b6 & 0xFFL) << 16 | (b7 & 0xFFL) << 8 | (b8 & 0xFFL)
  }
}
