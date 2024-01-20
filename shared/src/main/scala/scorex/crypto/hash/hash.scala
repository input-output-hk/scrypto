package scorex.crypto

import scala.language.implicitConversions

//import supertagged.TaggedType

package object hash {

//  trait BaseDigest extends TaggedType[Array[Byte]]

//  type Digest = BaseDigest#Type

//  object Digest32 extends BaseDigest
//
//  type Digest32 = Digest32.Type

  def @@[C](c: Array[Byte]): C = unsafeCast(c)
  def @@[C](c: Byte): C = unsafeCast(c)

  def @@@[A, B](c: A): B = unsafeCast(c)

  @inline final def unsafeCast[A, B](v: A): B = v.asInstanceOf[B]
  implicit def digest32ToArray(dig: Digest32): Array[Byte] = dig.value
  implicit def digest64ToArray(dig: Digest64): Array[Byte] = dig.value
  implicit def digestToArray(dig: Digest): Array[Byte] = dig.value

  trait Digest extends Any {
    val value: Array[Byte]

    def toList: List[Byte] = value.toList
  }

//  case class Digest(val value: Array[Byte]) extends AnyVal with BaseDigest

  case class Digest32(value: Array[Byte]) extends AnyVal with Digest

  case class Digest64(value: Array[Byte]) extends AnyVal with Digest
//  object Digest64 extends BaseDigest

//  type Digest64 = Digest64.Type

//  object NonStandardDigest extends BaseDigest

//  type NonStandardDigest = NonStandardDigest.Type
  case class NonStandardDigest(val value: Array[Byte]) extends AnyVal

  type ExtendedDigest = Platform.Digest

  def createBlake2bDigest(bitSize: Int): ExtendedDigest = Platform.createBlake2bDigest(bitSize)

  def createSha256Digest(): ExtendedDigest = Platform.createSha256Digest()

  def updateDigest(digest: ExtendedDigest, b: Byte) = Platform.updateDigest(digest, b)

  def updateDigest(digest: ExtendedDigest, in: Array[Byte], inOff: Int, inLen: Int) = Platform.updateDigest(digest, in, inOff, inLen)

  def doFinalDigest(digest: ExtendedDigest): Array[Byte] = Platform.doFinalDigest(digest)
}
