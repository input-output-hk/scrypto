package scorex.crypto.hash

object Platform {


  case class Digest()
  
  def createBlake2bDigest(bitSize: Int): Digest = ???

  def createSha256Digest(): Digest = ???

  def updateDigest(digest: Digest, b: Byte) = ???

  def updateDigest(digest: Digest,
                   in: Array[Byte],
                   inOff: Int,
                   inLen: Int) = {
    ???
  }

  def doFinalDigest(digest: Digest): Array[Byte] = {
    ???
  }
}
