package scorex.crypto.hash

object Keccak256 extends Keccak[Digest32] with CryptographicHash32 {
  override def hash(input: Message): Digest32 = Digest32 @@ internalHash(input)
}
