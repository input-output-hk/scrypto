package scorex.crypto.encode

import java.io.IOException

import org.bouncycastle.util.encoders.Hex

import scala.util.{Failure, Success, Try}

object Base16 extends BytesEncoder {

  override val Alphabet: String = "0123456789abcdefABCDEF"
  private val hexArray = "0123456789abcdef".toCharArray

  private val hexIndex: Array[Byte] = {
     var index = Array.fill[Byte](128)(0xff.toByte)
     hexArray.zipWithIndex.foreach { case (c, i) =>
        index(c) = i.toByte
     }
     "abcdef".toCharArray.foreach{ c =>
       index(c.toUpper) = index(c)
     }
    index
  }

  def encode(input: Array[Byte]): String = {
    val buf = new Array[Char](input.length * 2)
    var j = 0
    while (j < input.length) {
      val v = input(j) & 0xFF
      buf(j * 2) = hexArray(v >>> 4)
      buf(j * 2 + 1)= hexArray(v & 0x0F)
      j += 1
    }
    new String(buf)
  }

  def decode(input: String): Try[Array[Byte]] = {
    var (isError, errorMsg) = if (input.length % 2 == 0) {
      (false, "")
    } else {
      (true, s"invalid length ${input.length} of Hex data")
    }

    val out = Array.ofDim[Byte](input.length / 2)
    var j = 0
    while (j < input.length && !isError) {
      val c1 = input(j)
      val c2 = input(j + 1)
      if (c1 > 0 && c1 < 127 && c2 > 0 && c2 < 127) {
        val b1 = hexIndex(c1)
        val b2 = hexIndex(c2)
        if ((b1 | b2) < 0) {
          isError = true
          errorMsg = "invalid characters encountered in Hex data"
        } else {
          out(j / 2) = ((b1 << 4) | b2).toByte
        }
      } else {
        isError = true
        errorMsg = "invalid characters encountered in Hex data"
      }
      j += 2
    }

    if (!isError) {
      Success(out)
    } else {
      Failure(new IOException(errorMsg))
    }
  }
}