package scorex.crypto.authds.legacy.treap

import scorex.crypto.authds.{ADKey, ADValue}

object Constants {

  val MaxKeySize = 512
  val PositiveInfinity: (ADKey, ADValue) = (ADKey @@ Array.fill(MaxKeySize)(-1: Byte), ADValue @@ Array[Byte]())
  val NegativeInfinity: (ADKey, ADValue) = (ADKey @@ Array.fill(1)(0: Byte), ADValue @@ Array[Byte]())

  val LabelOfNone: Array[Byte] = Array()
  type LevelFunction = ADKey => Level

}
