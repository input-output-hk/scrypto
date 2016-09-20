package scorex.crypto.authds.avltree

import com.google.common.primitives.Ints
import scorex.crypto.hash.Sha256
import scorex.utils.ByteArray

case class Level(level: Int) extends Ordered[Level] {

  val bytes: Array[Byte] = Ints.toByteArray(level)

  override def compare(that: Level): Int = level.compareTo(that.level)
}

object Level {

  implicit def fromInt(level: Int): Level = Level(level)
  implicit def toInt(level: Level): Int = level.level
  def generator(key: WTKey): Level = Ints.fromByteArray(Sha256(key).take(4))
}