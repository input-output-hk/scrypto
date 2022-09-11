package scorex.crypto

import supertagged.TaggedType

package object hash {

  trait BaseDigest extends TaggedType[Array[Byte]]

  type Digest = BaseDigest#Type

  object Digest32 extends BaseDigest

  type Digest32 = Digest32.Type

  object Digest64 extends BaseDigest

  type Digest64 = Digest64.Type

  object NonStandardDigest extends BaseDigest

  type NonStandardDigest = NonStandardDigest.Type

}
