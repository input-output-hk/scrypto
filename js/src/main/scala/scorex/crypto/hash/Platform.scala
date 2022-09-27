package scorex.crypto.hash

import scorex.crypto.BouncycastleJs

import scala.scalajs.js

object Platform {

  type Digest = BouncycastleJs.Digest
  
  def createBlake2bDigest(bitSize: Int): Digest = {
    val bc = BouncycastleJs.bouncyCastle
    val digest = bc.createBlake2bDigest(bitSize)
    digest
  }

  def createSha256Digest(): Digest = {
    val bc = BouncycastleJs.bouncyCastle
    val digest = bc.createSha256Digest()
    digest
  }

  def updateDigest(digest: Digest, b: Byte): Unit = {
    digest.updateByte(b)
  }

  def updateDigest(digest: Digest,
                   bytes: Array[Byte],
                   inOff: Int,
                   inLen: Int): Unit = {
    val in = BouncycastleJs.createByteArrayFromData(js.Array(bytes: _*))
    digest.update(in, inOff, inLen)
  }

  def doFinalDigest(digest: Digest): Array[Byte] = {
    val res = BouncycastleJs.createByteArrayFromData(new js.Array[Byte](32))
    digest.doFinal(res, 0)
    res.data.toArray
  }
}
