package scorex.crypto.authds.legacy.treap

import scorex.crypto.authds.{ADKey, ADValue}

object Constants {
  type TreapKey = ADKey
  type TreapValue = ADValue

  val MaxKeySize = 512
  val PositiveInfinity: (TreapKey, TreapValue) = (ADKey @@ Array.fill(MaxKeySize)(-1: Byte), ADValue @@ Array[Byte]())
  val NegativeInfinity: (TreapKey, TreapValue) = (ADKey @@ Array.fill(1)(0: Byte), ADValue @@ Array[Byte]())

  val LabelOfNone: Array[Byte] = Array()
  type LevelFunction = TreapKey => Level

}
