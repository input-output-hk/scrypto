package scorex.crypto.authds.skiplist

sealed trait SLElement extends Ordered[SLElement] {
  val key: Array[Byte]
  val value: Array[Byte]

  override def compare(that: SLElement): Int = scorex.crypto.compare(key, that.key)
}

case class NormalSLElement(key: Array[Byte], value: Array[Byte]) extends SLElement {

  require(this < MaxSLElement)
  require(this > MinSLElement)
}

case object MaxSLElement extends SLElement {
  override val key: Array[Byte] = Array.fill(SLElement.MaxKeySize)(1: Byte)
  override val value: Array[Byte] = Array.empty
}

case object MinSLElement extends SLElement {
  override val key: Array[Byte] = (-128: Byte) +: Array.fill(SLElement.MaxKeySize - 1)(1: Byte)
  override val value: Array[Byte] = Array.empty
}

object SLElement {

  val MaxKeySize = 512

  def apply(key: Array[Byte], value: Array[Byte]): NormalSLElement = NormalSLElement(key, value)

}
