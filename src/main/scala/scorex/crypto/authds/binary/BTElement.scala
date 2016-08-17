package scorex.crypto.authds.binary

import scorex.utils.ByteArray

sealed trait BTElement extends Ordered[BTElement] {
  val key: BTKey
  val value: BTValue

  def bytes: Array[Byte]

  override def compare(that: BTElement): Int = ByteArray.compare(key, that.key)

  def ==(that: BTElement): Boolean = compare(that) == 0
}
