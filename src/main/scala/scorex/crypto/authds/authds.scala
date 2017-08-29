package scorex.crypto

import supertagged.TaggedType

package object authds {

  object LeafData extends TaggedType[Array[Byte]]

  type LeafData = LeafData.Type

  object Side extends TaggedType[Byte]

  type Side = Side.Type

}
