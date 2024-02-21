package scorex.crypto

import scorex.crypto.utils.{NewByte, NewArrayByte}

package object authds:
  object LeafData extends NewArrayByte
  type LeafData = LeafData.Type

  object Side extends NewByte
  type Side = Side.Type

  object ADKey extends NewArrayByte
  type ADKey = ADKey.Type

  object ADValue extends NewArrayByte
  type ADValue = ADValue.Type

  object ADDigest extends NewArrayByte
  type ADDigest = ADDigest.Type

  object SerializedAdProof extends NewArrayByte
  type SerializedAdProof = SerializedAdProof.Type

  object Balance extends NewByte
  type Balance = Balance.Type

  /** Immutable empty array which can be used in many places to avoid allocations. */
  val EmptyByteArray = Array.empty[Byte]
end authds