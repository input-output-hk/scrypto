package scorex.crypto

import supertagged.TaggedType

package object hash {

  trait BaseDigest extends TaggedType[Array[Byte]]

  type Digest = BaseDigest#Type

  object Digest32 extends BaseDigest

  type Digest32 = Digest32.Type

  object Digest64 extends BaseDigest

  type Digest64 = Digest64.Type

  object NonStandardDigest extends BaseDigest

  type NonStandardDigest = NonStandardDigest.Type

  type ExtendedDigest = Platform.Digest

  def createBlake2bDigest(bitSize: Int): ExtendedDigest = Platform.createBlake2bDigest(bitSize)

  def createSha256Digest(): ExtendedDigest = Platform.createSha256Digest()

  def updateDigest(digest: ExtendedDigest, b: Byte) = Platform.updateDigest(digest, b)

  def updateDigest(digest: ExtendedDigest, in: Array[Byte], inOff: Int, inLen: Int) = Platform.updateDigest(digest, in, inOff, inLen)

  def doFinalDigest(digest: ExtendedDigest): Array[Byte] = Platform.doFinalDigest(digest)
}
