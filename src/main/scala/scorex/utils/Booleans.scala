package scorex.utils

object Booleans {

  lazy val trueArray = Array(1: Byte)

  lazy val falseArray = Array(0: Byte)

  def toByteArray(v: Boolean): Array[Byte] = if (v) trueArray else falseArray

  def fromByteArray(b: Array[Byte]): Boolean = if (b sameElements trueArray) true else false

}