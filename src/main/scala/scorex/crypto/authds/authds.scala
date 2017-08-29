package scorex.crypto

import supertagged.TaggedType

package object authds {

  object LeafData extends TaggedType[Array[Byte]]

  type LeafData = LeafData.Type

  object Side extends TaggedType[Byte]

  type Side = Side.Type

  object ADKey extends TaggedType[Array[Byte]]

  type ADKey = ADKey.Type

  object ADValue extends TaggedType[Array[Byte]]

  type ADValue = ADValue.Type

  object ADDigest extends TaggedType[Array[Byte]]

  type ADDigest = ADDigest.Type

  object ADProof extends TaggedType[Array[Byte]]

  type ADProof = ADProof.Type

  object Label extends TaggedType[Array[Byte]]

  type Label = Label.Type

  object Balance extends TaggedType[Byte]

  type Balance = Balance.Type


}
