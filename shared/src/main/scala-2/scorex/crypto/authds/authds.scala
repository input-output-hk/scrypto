package scorex.crypto

import supertagged.TaggedType

package object authds {

  type LeafData = LeafData.Type
  object LeafData extends TaggedType[Array[Byte]]

  type Side = Side.Type
  object Side extends TaggedType[Byte]

  type ADKey = ADKey.Type
  object ADKey extends TaggedType[Array[Byte]]

  type ADValue = ADValue.Type
  object ADValue extends TaggedType[Array[Byte]]

  type ADDigest = ADDigest.Type
  object ADDigest extends TaggedType[Array[Byte]]

  type SerializedAdProof = SerializedAdProof.Type
  object SerializedAdProof extends TaggedType[Array[Byte]]

  type Balance = Balance.Type
  object Balance extends TaggedType[Byte]

  /** Immutable empty array which can be used in many places to avoid allocations. */
  val EmptyByteArray = Array.empty[Byte]
}
