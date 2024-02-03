package scorex.crypto

import scorex.crypto.hash.{Digest, Digest32}

import scala.collection.mutable.WrappedArray
import scala.language.implicitConversions

package object authds {
  case class LeafData(value: Array[Byte]) extends AnyVal {
    def ++(c: Array[Byte]): Array[Byte] = value ++ c
    def sameElements(c: Array[Byte]): Boolean = value.sameElements(c)
  }
  object LeafData {
    def @@(c: Array[Byte]): LeafData = LeafData(c)

  }
  implicit def leafDataToArray(data: LeafData): Array[Byte] = data.value

  case class Side(value: Byte) extends AnyVal
  object Side {
    def @@(c: Byte): Side = Side(c)

  }
  implicit def sideToArray(data: Side): Byte = data.value
  case class ADKey(value: Array[Byte]) extends AnyVal {
    def sameElements(c: Array[Byte]): Boolean = value.sameElements(c)
    def +:(c: Byte): Array[Byte] = c +: value
  }
  object ADKey {
    def @@(c: Array[Byte]): ADKey = ADKey(c)
    def @@@(c: Digest32): ADKey = ADKey(c.value)

  }
  implicit def adkeyToArray(data: ADKey): Array[Byte] = data.value
  case class ADValue(value: Array[Byte]) extends AnyVal {
    def sameElements(c: Array[Byte]): Boolean = value.sameElements(c)
    def nonEmpty: Boolean = value.nonEmpty
  }
  object ADValue {
    def @@(c: Array[Byte]): ADValue = ADValue(c)
    def @@@(c: Digest32): ADValue = ADValue(c.value)

  }
  implicit def advalueToArray(data: ADValue): Array[Byte] = data.value
  case class ADDigest(value: Array[Byte]) extends AnyVal {
    def sameElements(c: Array[Byte]): Boolean = value.sameElements(c)
    def last: Byte = value.last
    def startsWith(c: Array[Byte]): Boolean = value.startsWith(c)
    def length: Int = value.length


  }
  object ADDigest {
    def @@(c: Array[Byte]): ADDigest = ADDigest(c)
    def @@@(c: Digest): ADDigest = ADDigest(c.value)

  }
  implicit def addigestToArray(data: ADDigest): Array[Byte] = data.value
  implicit def addigestToWArray(data: ADDigest): WrappedArray[Byte] = data.value

  case class SerializedAdProof(value: Array[Byte]) extends AnyVal {
    def slice(from: Int, until: Int): Array[Byte] = value.slice(from, until)

  }
  object SerializedAdProof {
    def @@(c: Array[Byte]): SerializedAdProof = SerializedAdProof(c)

  }
  implicit def adproofToArray(data: SerializedAdProof): Array[Byte] = data.value
  case class Balance(value: Byte) extends AnyVal {
    def ==(c: Int): Boolean = value.toInt == c
    def !=(c: Int): Boolean = value.toInt != c
  }
  object Balance {
    def @@(c: Byte): Balance = Balance(c)

  }
  implicit def balanceToArray(data: Balance): Byte = data.value
  
  /** Immutable empty array which can be used in many places to avoid allocations. */
  val EmptyByteArray = Array.empty[Byte]
}
