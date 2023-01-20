package scorex.crypto.hash

import org.bouncycastle.crypto.digests.{Blake2bDigest, SHA256Digest}

/** JVM platform specific implementation of methods.
  * When shared code is compiled to JVM, this implementation is used.
  *
  * The JVM implementation is based on bouncycastle library.

  * @see js/src/main/scala/scorex/crypto/hash/Platform.scala for JS implementation
  */
object Platform {

  /** Represents abstract digest from bouncycastle.
    * See createBlake2bDigest, createSha256Digest methods.
    */
  type Digest = org.bouncycastle.crypto.ExtendedDigest

  /** Creates an implementation of the cryptographic hash function Blakbe2b.
    *
    * @param bitSize the bit size of the digest
    * @return the digest implementation
    */
  def createBlake2bDigest(bitSize: Int): Digest = new Blake2bDigest(bitSize)

  /** Creates an implementation of the cryptographic hash function SHA-256.
    *
    * @return the digest implementation
    */
  def createSha256Digest(): Digest = new SHA256Digest()

  /** Update the message digest with a single byte.
    *
    * @param digest the digest to be updated
    * @param b the input byte to be entered.
    */
  def updateDigest(digest: Digest, b: Byte): Unit = digest.update(b)

  /** Update the message digest with a block of bytes.
    *
    * @param digest the digest to be updated
    * @param in     the byte array containing the data.
    * @param inOff  the offset into the byte array where the data starts.
    * @param inLen  the length of the data.
    */
  def updateDigest(digest: Digest,
                   in: Array[Byte],
                   inOff: Int,
                   inLen: Int): Unit = {
    digest.update(in, inOff, inLen)
  }

  /** Close the digest, producing the final digest value. The doFinal
    * call leaves the digest reset.
    * A new array is created to store the result.
    *
    * @param digest the digest to be finalized
    */
  def doFinalDigest(digest: Digest): Array[Byte] = {
    val res = new Array[Byte](digest.getDigestSize)
    digest.doFinal(res, 0)
    res
  }
}
