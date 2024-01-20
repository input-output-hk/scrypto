package scorex.crypto.authds.legacy.treap

import scorex.utils.Ints
import scorex.crypto.authds._
import scorex.crypto.hash.Sha256
import scorex.utils.ByteArray



trait Level extends Ordered[Level] {
  val bytes: Array[Byte]
}

object Level {
  def skiplistLevel(key: ADKey): Level = {
    def isBitSet(byte: Byte)(bit: Int): Boolean =
      ((byte >> bit) & 1) == 1

    val s = Sha256(key)
    var i = 0
    while (i < 256 && !isBitSet(s.value(i / 8))(i % 8)) i = i + 1
    ByteLevel(i.toByte)
  }

  def treapLevel(key: ADKey): Level = IntLevel(Ints.fromByteArray(Sha256(key).value.take(4)))
}


case class IntLevel(level: Int) extends Level {
  override val bytes: Array[Byte] = Ints.toByteArray(level)

  override def compare(that: Level): Int = that match {
    case IntLevel(r) => level.compareTo(r)
    case _ => ByteArray.compare(bytes, that.bytes)
  }
}

case class ByteLevel(level: Byte) extends Level {
  override val bytes: Array[Byte] = Array(level)

  override def compare(that: Level): Int = that match {
    case ByteLevel(r) => level.compareTo(r)
    case _ => ByteArray.compare(bytes, that.bytes)
  }
}
