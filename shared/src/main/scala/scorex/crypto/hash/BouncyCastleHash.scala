package scorex.crypto.hash

/** Default implementation of hash generation using bouncycastle-style pair of methods
  * update/doFinal.
  * The only thing you need to do is to provide digestFn, which creates the correct digest
  * for your hash function.
  */
trait BouncyCastleHash[D <: Digest] extends CryptographicHash[D] {

  /** Compute the hash by creating a digest, updating it with the messages and then
    * finalizing. */
  protected def internalHash(inputs: Message*): Array[Byte] = synchronized {
    val digest = digestFn
    inputs.foreach(i => updateDigest(digest, i, 0, i.length))
    doFinalDigest(digest)
  }

  /** Compute the hash by creating a digest, updating it with the prefix and the messages
    * and then finalizing. */
  protected def internalPrefixedHash(prefix: Byte, inputs: Message*): Array[Byte] = synchronized {
    val digest = digestFn
    updateDigest(digest, prefix)
    inputs.foreach(i => updateDigest(digest, i, 0, i.length))
    doFinalDigest(digest)
  }

  /** Should be overriden to provide appropriate Digest instance. */
  protected def digestFn: ExtendedDigest
}
