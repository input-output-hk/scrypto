package scorex.crypto

package object encode {

  @deprecated("Use scorex.util.encode.BytesEncoder instead.", "scorex-util 0.1.1")
  type BytesEncoder = scorex.util.encode.BytesEncoder

  @deprecated("Use scorex.util.encode.Base16 instead.", "scorex-util 0.1.1")
  val Base16 = scorex.util.encode.Base16
  @deprecated("Use scorex.util.encode.Base58 instead.", "scorex-util 0.1.1")
  val Base58 = scorex.util.encode.Base58
  @deprecated("Use scorex.util.encode.Base64 instead.", "scorex-util 0.1.1")
  val Base64 = scorex.util.encode.Base64
}
