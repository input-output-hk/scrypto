package scorex.crypto.hash

object Blake2b512 extends Blake2b[Digest64] with CryptographicHash64 {
  override def hash(input: Message): Digest64 = Digest64 @@ internalHash(input)

  override def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Digest64 =
    Digest64 @@ internalPrefixedHash(prefix, inputs: _*)

}
