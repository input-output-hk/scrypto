package scorex.crypto.authds

import scorex.crypto.hash.CryptographicHash

import scala.util.Try

package object avltree {
  type Level = Int
  type AVLKey = Array[Byte]
  type AVLValue = Array[Byte]
  type Label = CryptographicHash#Digest
  val MaxKeySize = 512
  val PositiveInfinity: (Array[Byte], Array[Byte]) = (Array.fill(MaxKeySize)(-1: Byte), Array())
  val NegativeInfinity: (Array[Byte], Array[Byte]) = (Array.fill(1)(0: Byte), Array())

  val LabelOfNone: Array[Byte] = Array()
  type UpdateFunction = Option[AVLValue] => Try[AVLValue]
  type LevelFunction = AVLKey => Level

}
