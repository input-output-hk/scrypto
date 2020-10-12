package scorex.crypto

import supertagged.TaggedType

package object authds {

  type LeafData = LeafData.Type
  type Side = Side.Type
  type ADKey = ADKey.Type
  type ADValue = ADValue.Type
  type ADDigest = ADDigest.Type
  type SerializedAdProof = SerializedAdProof.Type
  type Balance = Balance.Type

  object LeafData extends TaggedType[Array[Byte]]

  object Side extends TaggedType[Byte]

  object ADKey extends TaggedType[Array[Byte]]

  object ADValue extends TaggedType[Array[Byte]]

  object ADDigest extends TaggedType[Array[Byte]]

  object SerializedAdProof extends TaggedType[Array[Byte]]

  object Balance extends TaggedType[Byte]

  /** Immutable empty array which can be used in many places to avoid allocations. */
  val EmptyByteArray = Array.empty[Byte]
}
