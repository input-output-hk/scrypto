package scorex.crypto.hash

import org.bouncycastle.crypto.digests.{Blake2bDigest, SHA256Digest}

object Platform {

  type Digest = org.bouncycastle.crypto.ExtendedDigest
  
  def createBlake2bDigest(bitSize: Int): Digest = new Blake2bDigest(bitSize)

  def createSha256Digest(): Digest = new SHA256Digest()

  def updateDigest(digest: Digest, b: Byte): Unit = digest.update(b)

  def updateDigest(digest: Digest,
                   in: Array[Byte],
                   inOff: Int,
                   inLen: Int): Unit = {
    digest.update(in, inOff, inLen)
  }

  def doFinalDigest(digest: Digest): Array[Byte] = {
    val res = new Array[Byte](digest.getDigestSize)
    digest.doFinal(res, 0)
    res
  }
}
