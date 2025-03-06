package scorex.crypto

import scala.language.implicitConversions

package object authds {

  opaque type LeafData <: Array[Byte] = Array[Byte]
  object LeafData {
    def @@(a: Array[Byte]): LeafData = a
    def @@@[A <: Array[Byte]](a: A): LeafData = a
    given Conversion[LeafData, Array[Byte]] = identity
  }

  opaque type Side <: Byte = Byte
  object Side {
    def @@(a: Byte): Side = a
    def @@@[A <: Byte](a: A): Side = a
    given Conversion[Side, Byte] = identity
  }

  opaque type ADKey <: Array[Byte] = Array[Byte]
  object ADKey {
    def @@(a: Array[Byte]): ADKey = a
    def @@@[A <: Array[Byte]](a: A): ADKey = a
    given Conversion[ADKey, Array[Byte]] = identity
  }

  opaque type ADValue <: Array[Byte] = Array[Byte]
  object ADValue {
    def @@(a: Array[Byte]): ADValue = a
    def @@@[A <: Array[Byte]](a: A): ADValue = a
    given Conversion[ADValue, Array[Byte]] = identity
  }

  opaque type ADDigest <: Array[Byte] = Array[Byte]
  object ADDigest {
    def @@(a: Array[Byte]): ADDigest = a
    def @@@[A <: Array[Byte]](a: A): ADDigest = a
  }

  opaque type SerializedAdProof <: Array[Byte] = Array[Byte]
  object SerializedAdProof {
    def @@(a: Array[Byte]): SerializedAdProof = a
    given Conversion[SerializedAdProof, Array[Byte]] = identity
  }

  opaque type Balance <: Byte = Byte
  object Balance {
    def @@(a: Byte): Balance = a
    given Conversion[Balance, Byte] = identity
  }

  /** Immutable empty array which can be used in many places to avoid allocations. */
  val EmptyByteArray = Array.empty[Byte]
}
