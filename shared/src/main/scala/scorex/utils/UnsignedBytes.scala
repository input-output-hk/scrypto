package scorex.utils

import java.util.Comparator

/**
  * Static utility methods pertaining to {@code byte} primitives that interpret values as
  * <i>unsigned</i> (that is, any negative value {@code b} is treated as the positive value
  * {@code 256 + b}).
  */
object UnsignedBytes {

  private val UNSIGNED_MASK = 0xFF

  /**
    * Returns the value of the given byte as an integer, when treated as unsigned. That is, returns
    * {@code value + 256} if {@code value} is negative; {@code value} itself otherwise.
    */
  @inline def toInt(value: Byte): Int = value & UNSIGNED_MASK

  /**
    * Compares the two specified {@code byte} values, treating them as unsigned values between 0 and
    * 255 inclusive. For example, {@code (byte) -127} is considered greater than {@code (byte) 127}
    * because it is seen as having the value of positive {@code 129}.
    *
    * @param a the first {@code byte} to compare
    * @param b the second {@code byte} to compare
    * @return a negative value if {@code a} is less than {@code b}; a positive value if {@code a} is
    *         greater than {@code b}; or zero if they are equal
    */
  @inline def compare(a: Byte, b: Byte): Int = toInt(a) - toInt(b)

  /**
    * Returns a comparator that compares two {@code byte} arrays <a
    * href="http://en.wikipedia.org/wiki/Lexicographical_order">lexicographically</a>. That is, it
    * compares, using {@link # compare ( byte, byte)}), the first pair of values that follow any common
    * prefix, or when one array is a prefix of the other, treats the shorter array as the lesser. For
    * example, {@code [] < [0x01] < [0x01, 0x7F] < [0x01, 0x80] < [0x02]}. Values are treated as
    * unsigned.
    *
    * <p>The returned comparator is inconsistent with {@link Object# equals ( Object )} (since arrays
    * support only identity equality), but it is consistent with
    * {@link java.util.Arrays# equals ( byte [ ], byte[])}.
    */
  // TODO optimize: use Unsafe for more efficient implementation (as in original guava)
  def lexicographicalComparator(): Comparator[Array[Byte]] = PureJavaComparator

  object PureJavaComparator extends Comparator[Array[Byte]] {

    override def compare(left: Array[Byte], right: Array[Byte]): Int = {
      val minLength = Math.min(left.length, right.length)
      var i = 0
      while (i < minLength) {
        val result = UnsignedBytes.compare(left(i), right(i))
        if (result != 0) return result
        i += 1
      }
      left.length - right.length
    }
    
  }

}

