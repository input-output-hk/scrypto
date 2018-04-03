package scorex.crypto.hash

import org.bouncycastle.crypto.ExtendedDigest

trait BouncyCastleHash[D <: Digest] extends CryptographicHash[D] {

  protected def internalHash(inputs: Message*): Array[Byte] = {
    inputs.foreach(i => digestFn.update(i, 0, i.length))
    val res = new Array[Byte](DigestSize)
    digestFn.doFinal(res, 0)
    res
  }

  protected def internalPrefixedHash(prefix: Byte, inputs: Message*): Array[Byte] = {
    digestFn.update(prefix)
    internalHash(inputs: _*)
  }

  protected def digestFn: ExtendedDigest
}
