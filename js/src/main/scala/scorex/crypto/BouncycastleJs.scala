package scorex.crypto

import scala.scalajs.js
import scala.annotation.nowarn
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Int8Array

@JSImport("bouncycastle-js", JSImport.Namespace)
@js.native
object BouncycastleJs extends js.Object {

  @js.native
  trait Digest extends js.Object {
    @nowarn
    def update(in: RtArray[Byte], inOff: Int, len: Int): Unit = js.native
    @nowarn
    def updateByte(b: Byte): Unit = js.native
    @nowarn
    def doFinal(out: RtArray[Byte], outOff: Int): Int = js.native
  }

  @js.native
  trait Crypto extends js.Object {
    def createBlake2bDigest(size: Int): Digest
    def createSha256Digest(): Digest
  }

  def bouncyCastle: Crypto = js.native

  @js.native
  trait RtArray[T] extends js.Object {
    def data: Int8Array
  }

  @nowarn
  def createByteArrayFromData(data: js.Array[Byte]): RtArray[Byte] = js.native
}