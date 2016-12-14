package scorex.crypto.hash

import scorex.crypto.utils.NatConstants.Nat32
import shapeless.Sized

trait CryptographicHash32 extends CryptographicHash {

  type SizedDigest = Sized[Array[Byte], Nat32]

  override val DigestSize: Int = 32

  def hashSized(in: Message): SizedDigest = Sized.wrap(hash(in))

  def hashSized(in: String): SizedDigest = hashSized(in.getBytes)

}
