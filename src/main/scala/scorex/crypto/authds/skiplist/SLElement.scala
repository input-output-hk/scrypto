package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.authds.skiplist.SkipList.{SLKey, SLValue}
import scorex.utils.ByteArray

import scala.util.Try

sealed trait SLElement extends Ordered[SLElement] {
  val key: SLKey
  val value: SLValue

  lazy val bytes: Array[Byte] = Ints.toByteArray(key.length) ++ Ints.toByteArray(value.length) ++ key ++ value

  override def compare(that: SLElement): Int = ByteArray.compare(key, that.key)

  def ==(that: SLElement): Boolean = compare(that) == 0
}

case class NormalSLElement(key: Array[Byte], value: Array[Byte]) extends SLElement {

  require(this < MaxSLElement)
  require(this > MinSLElement)


}

case object MaxSLElement extends SLElement {
  override val key: Array[Byte] = Array.fill(SLElement.MaxKeySize)(-1: Byte)
  override val value: Array[Byte] = Array(127: Byte)

}

case object MinSLElement extends SLElement {
  override val key: Array[Byte] = Array.fill(1)(0: Byte)
  override val value: Array[Byte] = Array(-128: Byte)
}

object SLElement {

  val MaxKeySize = 512

  def apply(key: Array[Byte], value: Array[Byte]): NormalSLElement = NormalSLElement(key, value)

  def parseBytes(bytes: Array[Byte]): Try[SLElement] = Try {
    val keySize = Ints.fromByteArray(bytes.slice(0, 4))
    if (keySize == SLElement.MaxKeySize) MaxSLElement
    else if (keySize == 1) MinSLElement
    else {
      val valueSize = Ints.fromByteArray(bytes.slice(4, 8))
      val key = bytes.slice(8, 8 + keySize)
      val value = bytes.slice(8 + keySize, 8 + keySize + valueSize)
      NormalSLElement(key, value)
    }
  }

}
