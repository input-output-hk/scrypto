package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.authds.skiplist.SkipList.{SLKey, SLValue}
import scorex.utils.ByteArray

sealed trait SLElement extends Ordered[SLElement] {
  val key: SLKey
  val value: SLValue

  def bytes: Array[Byte]

  override def compare(that: SLElement): Int = ByteArray.compare(key, that.key)

  def ==(that: SLElement): Boolean = compare(that) == 0
}

case class NormalSLElement(key: Array[Byte], value: Array[Byte]) extends SLElement {

  require(this < MaxSLElement)
  require(this > MinSLElement)

  lazy val bytes: Array[Byte] = Ints.toByteArray(key.length) ++ Ints.toByteArray(value.length) ++ key ++ value

}

case object MaxSLElement extends SLElement {
  override val key: Array[Byte] = Array.fill(SLElement.MaxKeySize)(127: Byte)
  override val value: Array[Byte] = Array(127: Byte)

  override lazy val bytes = Ints.toByteArray(-1)
}

case object MinSLElement extends SLElement {
  override val key: Array[Byte] = Array.fill(SLElement.MaxKeySize)(-128: Byte)
  override val value: Array[Byte] = Array(-128: Byte)
  override lazy val bytes = Ints.toByteArray(-2)
}

object SLElement {

  val MaxKeySize = 512

  def apply(key: Array[Byte], value: Array[Byte]): NormalSLElement = NormalSLElement(key, value)

  def parseBytes(bytes: Array[Byte]): SLElement = {
    val keySize = Ints.fromByteArray(bytes.slice(0, 4))
    if (keySize == -1) MaxSLElement
    else if (keySize == -2) MinSLElement
    else {
      val valueSize = Ints.fromByteArray(bytes.slice(4, 8))
      val key = bytes.slice(8, 8 + keySize)
      val value = bytes.slice(8 + keySize, 8 + keySize + valueSize)
      NormalSLElement(key, value)
    }
  }

}
