package scorex.crypto.hash

import org.bouncycastle.crypto.ExtendedDigest

trait BouncycastleHash extends CryptographicHash {
  override def hash(input: Message): Digest = synchronized {
    digestFn.update(input, 0, input.length)
    val res = new Array[Byte](DigestSize)
    digestFn.doFinal(res, 0)
    res
  }

  protected def digestFn: ExtendedDigest

}
