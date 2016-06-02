package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.authds.skiplist.SkipList.{SLKey, SLValue}
import scorex.utils.ByteArray

sealed trait SLElement extends Ordered[SLElement] {
  val key: SLKey
  val value: SLValue
  lazy val bytes = Ints.toByteArray(key.length) ++ Ints.toByteArray(value.length) ++ key ++ value

  override def compare(that: SLElement): Int = ByteArray.compare(key, that.key)

  def ==(that: SLElement): Boolean = compare(that) == 0
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

  def parseBytes(bytes: Array[Byte]): SLElement = {
    val keySize = Ints.fromByteArray(bytes.slice(0, 4))
    val valueSize = Ints.fromByteArray(bytes.slice(4, 8))
    val key = bytes.slice(8, 8 + keySize)
    lazy val value = bytes.slice(8 + keySize, 8 + keySize + valueSize)
    if (key sameElements MinSLElement.key) MinSLElement
    else if (key sameElements MaxSLElement.key) MaxSLElement
    else NormalSLElement(key, value)
  }

}
