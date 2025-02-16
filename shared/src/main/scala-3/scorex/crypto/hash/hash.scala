package scorex.crypto

package object hash {

  trait BaseDigest
  opaque type Digest <: Array[Byte] = Array[Byte]

  opaque type Digest32 <: Digest & Array[Byte] = Array[Byte]
  opaque type Digest64 <: Digest & Array[Byte] = Array[Byte]
  opaque type NonStandardDigest <: Digest & Array[Byte] = Array[Byte]

  object Digest32 extends BaseDigest {
    def @@(a: Array[Byte]): Digest32 = a
    given Conversion[Digest32, Array[Byte]] = identity
  }

  object Digest64 extends BaseDigest {
    def @@(a: Array[Byte]): Digest64 = a
    given Conversion[Digest64, Array[Byte]] = identity
  }

  object NonStandardDigest extends BaseDigest

  type ExtendedDigest = Platform.Digest

  def createBlake2bDigest(bitSize: Int): ExtendedDigest = Platform.createBlake2bDigest(bitSize)

  def createSha256Digest(): ExtendedDigest = Platform.createSha256Digest()

  def updateDigest(digest: ExtendedDigest, b: Byte) = Platform.updateDigest(digest, b)

  def updateDigest(digest: ExtendedDigest, in: Array[Byte], inOff: Int, inLen: Int) = Platform.updateDigest(digest, in, inOff, inLen)

  def doFinalDigest(digest: ExtendedDigest): Array[Byte] = Platform.doFinalDigest(digest)
}
