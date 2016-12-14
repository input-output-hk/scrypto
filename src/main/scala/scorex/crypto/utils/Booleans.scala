package scorex.crypto.utils

object Booleans {

  def toByteArray(v: Boolean): Array[Byte] = if (v) Array(1: Byte) else Array(0: Byte)

  def fromByteArray(b: Array[Byte]): Boolean = if (b sameElements Array(1: Byte)) true else false

}
