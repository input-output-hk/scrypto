package scorex.crypto.hash

object Keccak256 extends Keccak[Digest32] with CryptographicHash32 {
  override def hash(input: Message): Digest32 = Digest32 @@ internalHash(input)

  override def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Digest32 =
    Digest32 @@ internalPrefixedHash(prefix, inputs: _*)

}
