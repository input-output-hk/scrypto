package scorex.crypto.authds.avltree

import com.google.common.primitives.Ints
import scorex.crypto.hash.Sha256
import scorex.utils.ByteArray

trait Level extends Ordered[Level] {

  val bytes: Array[Byte]
}

case class ByteLevel(level: Byte) extends Level {
  override val bytes: Array[Byte] = Array(level)

  override def compare(that: Level): Int = that match {
    case ByteLevel(r) => level.compareTo(r)
    case _ => ByteArray.compare(bytes, that.bytes)
  }
}

case class IntLevel(level: Int) extends Level {
  override val bytes: Array[Byte] = Ints.toByteArray(level)

  override def compare(that: Level): Int = that match {
    case IntLevel(r) => level.compareTo(r)
    case _ => ByteArray.compare(bytes, that.bytes)
  }
}


object Level {
  def skiplistLevel(key: WTKey): Level = {
    def isBitSet(byte: Byte)(bit: Int): Boolean =
      ((byte >> bit) & 1) == 1
    def byte2Bools(b: Byte): Seq[Boolean] = 0 to 7 map isBitSet(b)

    ByteLevel(Sha256(key).flatMap(b => byte2Bools(b)).indexOf(true).toByte)
  }

  def treapLevel(key: WTKey): Level = IntLevel(Ints.fromByteArray(Sha256(key).take(4)))

}