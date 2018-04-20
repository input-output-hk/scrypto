package scorex.crypto.encode

import scala.util.Try

/**
  * A custom form of base58 is used to encode Scorex addresses.
  */
object Base58 extends BytesEncoder {
  val Alphabet: String = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  private val DecodeTable = Array(
    0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1, -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1,
    44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57
  )

  private val Base = BigInt(58)

  override def encode(input: Array[Byte]): String = {
    var bi = BigInt(1, input)
    val s = new StringBuilder()
    if (bi > 0) {
      while (bi >= Base) {
        val (newBi, mod) = bi /% Base
        s.insert(0, Alphabet.charAt(mod.intValue()))
        bi = newBi
      }
      s.insert(0, Alphabet.charAt(bi.intValue()))
    }
    // Convert leading zeros too.
    input.takeWhile(_ == 0).foldLeft(s) { case (ss, _) =>
      ss.insert(0, Alphabet.charAt(0))
    }.toString()
  }

  override def decode(input: String): Try[Array[Byte]] = Try {
    require(input.length > 0, "Empty input for Base58.decode")

    val decoded = decodeToBigInteger(input)

    val bytes: Array[Byte] = if (decoded == BigInt(0)) Array.empty else decoded.toByteArray
    // We may have got one more byte than we wanted, if the high bit of the next-to-last byte was not zero.
    // This  is because BigIntegers are represented with twos-compliment notation,
    // thus if the high bit of the last  byte happens to be 1 another 8 zero bits will be added to
    // ensure the number parses as positive. Detect that case here and chop it off.
    val stripSignByte = bytes.length > 1 && bytes.head == 0 && bytes(1) < 0
    val stripSignBytePos = if (stripSignByte) 1 else 0
    // Count the leading zeros, if any.
    val leadingZeros = input.takeWhile(_ == Alphabet.charAt(0)).length

    // Now cut/pad correctly. Java 6 has a convenience for this, but Android
    // can't use it.
    val tmp = new Array[Byte](bytes.length - stripSignBytePos + leadingZeros)
    System.arraycopy(bytes, stripSignBytePos, tmp, leadingZeros, tmp.length - leadingZeros)
    tmp
  }

  private def decodeToBigInteger(input: String): BigInt =
  // Work backwards through the string.
    input.foldRight((BigInt(0), BigInt(1))) { case (ch, (bi, k)) =>
      val alphaIndex = toBase58(ch).ensuring(_ != -1, "Wrong char in Base58 string")
      (bi + BigInt(alphaIndex) * k, k * Base)
    }._1

  private def toBase58(c: Char): Int = {
    val x = c.toInt
    if (x < 49) -1 else if (x <= 122) DecodeTable(x - 49) else -1
  }
}