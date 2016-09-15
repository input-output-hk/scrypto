package scorex.crypto.authds.wtree

import scorex.crypto.encode.Base58

sealed trait WTProofElement {
  val bytes: Array[Byte]
}

case class WTProofLevel(e: Byte) extends WTProofElement {
  val bytes: Array[Byte] = Array(e)
}

trait WTProofLabel extends WTProofElement {
  val e: Array[Byte]
  val bytes: Array[Byte] = e

  override def toString: String = s"WTProofKey(${Base58.encode(e).take(8)})"
}

case class WTProofRightLabel(e: Array[Byte]) extends WTProofLabel

case class WTProofLeftLabel(e: Array[Byte]) extends WTProofLabel

trait Key extends WTProofElement {
  val e: Array[Byte]
  val bytes: Array[Byte] = e

  override def toString: String = s"Key(${Base58.encode(e).take(8)})"
}

case class WTProofKey(e: WTKey) extends Key
case class WTProofNextLeafKey(e: WTKey) extends Key

case class WTProofValue(e: WTValue) extends WTProofElement {
  val bytes: Array[Byte] = e

  override def toString: String = s"WTProofKey(${Base58.encode(e).take(8)})"
}

case class WTProofDirection(direction: Direction) extends WTProofElement {
  override val bytes: Array[Level] = Array(direction match {
    case LeafFound => 1: Byte
    case LeafNotFound => 2: Byte
    case GoingLeft => 3: Byte
    case GoingRight => 4: Byte
  })
}

sealed trait Direction

case object LeafFound extends Direction {}

case object LeafNotFound extends Direction

case object GoingLeft extends Direction

case object GoingRight extends Direction
