package scorex.crypto

import supertagged.TaggedType

package object signatures {

  object PrivateKey extends TaggedType[Array[Byte]]

  type PrivateKey = PrivateKey.Type

  object PublicKey extends TaggedType[Array[Byte]]

  type PublicKey = PublicKey.Type

  object SharedSecret extends TaggedType[Array[Byte]]

  type SharedSecret = SharedSecret.Type

  object Signature extends TaggedType[Array[Byte]]

  type Signature = Signature.Type

  type MessageToSign = Array[Byte]

}
