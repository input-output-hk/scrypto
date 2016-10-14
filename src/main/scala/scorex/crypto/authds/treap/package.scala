package scorex.crypto.authds

package object treap {
  type TreapKey = Array[Byte]
  type TreapValue = Array[Byte]

  val MaxKeySize = 512
  val PositiveInfinity: (Array[Byte], Array[Byte]) = (Array.fill(MaxKeySize)(-1: Byte), Array())
  val NegativeInfinity: (Array[Byte], Array[Byte]) = (Array.fill(1)(0: Byte), Array())

  val LabelOfNone: Array[Byte] = Array()
  type LevelFunction = TreapKey => Level

}
