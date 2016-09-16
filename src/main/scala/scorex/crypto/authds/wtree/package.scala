package scorex.crypto.authds

import scorex.crypto.hash.{CryptographicHash, Sha256}

package object wtree {
  type WTKey = Array[Byte]
  type WTValue = Array[Byte]
  type Label = CryptographicHash#Digest
  type Level = Byte

  val MaxKeySize = 512
  val PositiveInfinity: (Array[Byte], Array[Byte]) = (Array.fill(MaxKeySize)(-1: Byte), Array())
  val NegativeInfinity: (Array[Byte], Array[Byte]) = (Array.fill(1)(0: Byte), Array())

  val LabelOfNone: Array[Byte] = Array()
  type UpdateFunction = Option[WTValue] => WTValue

  //TODO check
  def levelFromKey(key: WTKey): Level = {
    def isBitSet(byte: Byte)(bit: Int): Boolean =
      ((byte >> bit) & 1) == 1
    def byte2Bools(b: Byte): Seq[Boolean] = 0 to 7 map isBitSet(b)

    Sha256(key).flatMap(b => byte2Bools(b)).indexOf(true).toByte
  }
}
