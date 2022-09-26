package scorex.crypto.hash

trait BouncyCastleHash[D <: Digest] extends CryptographicHash[D] {

  protected def internalHash(inputs: Message*): Array[Byte] = synchronized {
    inputs.foreach(i => updateDigest(digestFn, i, 0, i.length))
    doFinalDigest(digestFn)
  }

  protected def internalPrefixedHash(prefix: Byte, inputs: Message*): Array[Byte] = synchronized {
    updateDigest(digestFn, prefix)
    inputs.foreach(i => updateDigest(digestFn, i, 0, i.length))
    doFinalDigest(digestFn)
  }

  protected def digestFn: ExtendedDigest
}
