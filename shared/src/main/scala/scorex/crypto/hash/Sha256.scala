package scorex.crypto.hash

/**
  * Hashing functions implementation with sha256 impl from Java SDK
  */
object Sha256 extends CryptographicHash32 with BouncyCastleHash[Digest32] {
  override def hash(input: Array[Byte]): Digest32 = @@[Digest32](internalHash(input))

  override protected def digestFn = createSha256Digest()

  override def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Digest32 =
    @@[Digest32](internalPrefixedHash(prefix, inputs: _*))
}