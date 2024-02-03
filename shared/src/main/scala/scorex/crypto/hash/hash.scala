package scorex.crypto

import scorex.crypto.authds.ADKey
import scorex.crypto.hash.Sha256.Message

package object hash {
  implicit def digest32ToArray(dig: Digest32): Array[Byte] = dig.value
  implicit def digest32ToMessage(dig: Digest32): Message = dig.value
  implicit def digest64ToArray(dig: Digest64): Array[Byte] = dig.value
  implicit def digestToArray(dig: Digest): Array[Byte] = dig.value
  trait Digest extends Any {
    val value: Array[Byte]
    def toList: List[Byte] = value.toList
    def ++(c: Array[Byte]): Array[Byte] = value ++ c
    def sameElements(c: Array[Byte]): Boolean = value.sameElements(c)
    def isEmpty: Boolean = value.isEmpty
    def :+(c: Byte): Array[Byte] = value :+ c
    def take(num: Int): Array[Byte] = value.take(num)

  }
  case class Digest32(value: Array[Byte]) extends AnyVal with Digest {
    def length: Int = value.length
  }
  object Digest32 {
    def @@(c: Array[Byte]): Digest32 = Digest32(c)
    def @@(c: Byte): Digest32 = Digest32(Array(c))
    def @@@(c: ADKey): Digest32 = Digest32(c.value)

  }
  case class Digest64(value: Array[Byte]) extends AnyVal with Digest
  object Digest64 {
    def @@(c: Array[Byte]): Digest64 = Digest64(c)
    def @@(c: Byte): Digest64 = Digest64(Array(c))

  }
  case class NonStandardDigest(value: Array[Byte]) extends AnyVal

  type ExtendedDigest = Platform.Digest

  def createBlake2bDigest(bitSize: Int): ExtendedDigest = Platform.createBlake2bDigest(bitSize)

  def createSha256Digest(): ExtendedDigest = Platform.createSha256Digest()

  def updateDigest(digest: ExtendedDigest, b: Byte) = Platform.updateDigest(digest, b)

  def updateDigest(digest: ExtendedDigest, in: Array[Byte], inOff: Int, inLen: Int) = Platform.updateDigest(digest, in, inOff, inLen)

  def doFinalDigest(digest: ExtendedDigest): Array[Byte] = Platform.doFinalDigest(digest)
}

