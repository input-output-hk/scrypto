package scorex.crypto.hash

import org.bouncycastle.crypto.digests.Blake2bDigest

object Platform {

  type Digest = org.bouncycastle.crypto.ExtendedDigest
  
  def createBlake2bDigest(bitSize: Int): Digest = new Blake2bDigest(bitSize)

  def updateDigest(digest: Digest, b: Byte) = digest.update(b)

  def updateDigest(digest: Digest,
                   in: Array[Byte],
                   inOff: Int,
                   inLen: Int) = {
    digest.update(in, inOff, inLen)
  }

  def doFinalDigest(digest: Digest): Array[Byte] = {
    val res = new Array[Byte](digest.getDigestSize)
    digest.doFinal(res, 0)
    res
  }
}
