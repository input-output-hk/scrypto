package scorex.crypto.hash

object Keccak512 extends Keccak[Digest64] with CryptographicHash64 {
  override def hash(input: Message): Digest64 = Digest64 @@ internalHash(input)
}
