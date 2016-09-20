package scorex.crypto.authds.wtree

import scorex.utils.ByteArray

trait Level extends Ordered[Level] {

  val bytes: Array[Byte]
}

case class ByteLevel(b: Byte) extends Level {
  override val bytes: Array[Byte] = Array(b)

  override def compare(that: Level): Int = that match {
    case ByteLevel(r) => b.compareTo(r)
    case _ => ByteArray.compare(bytes, that.bytes)
  }

}
