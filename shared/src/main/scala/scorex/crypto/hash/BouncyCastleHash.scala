package scorex.crypto.hash

trait BouncyCastleHash[D <: Digest] extends CryptographicHash[D] {

  protected def internalHash(inputs: Message*): Array[Byte] = synchronized {
    val digest = digestFn
    inputs.foreach(i => updateDigest(digest, i, 0, i.length))
    doFinalDigest(digest)
  }

  protected def internalPrefixedHash(prefix: Byte, inputs: Message*): Array[Byte] = synchronized {
    val digest = digestFn
    updateDigest(digest, prefix)
    inputs.foreach(i => updateDigest(digest, i, 0, i.length))
    doFinalDigest(digest)
  }

  protected def digestFn: ExtendedDigest
}
