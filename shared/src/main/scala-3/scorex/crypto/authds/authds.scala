package scorex.crypto

import scorex.crypto.utils.NewType

package object authds:
  object LeafData extends NewType[Array[Byte]]
  type LeafData = LeafData.Type

  object Side extends NewType[Byte]
  type Side = Side.Type

  object ADKey extends NewType[Array[Byte]]
  type ADKey = ADKey.Type

  object ADValue extends NewType[Array[Byte]]
  type ADValue = ADValue.Type

  object ADDigest extends NewType[Array[Byte]]
  type ADDigest = ADDigest.Type

  object SerializedAdProof extends NewType[Array[Byte]]
  type SerializedAdProof = SerializedAdProof.Type

  object Balance extends NewType[Byte]
  type Balance = Balance.Type

  /** Immutable empty array which can be used in many places to avoid allocations. */
  val EmptyByteArray = Array.empty[Byte]
end authds