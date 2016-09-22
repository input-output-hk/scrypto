package scorex.crypto.authds

import scorex.crypto.encode.Base58

trait TwoPartyProofElement {
  val bytes: Array[Byte]
}

sealed trait WTProofElement extends TwoPartyProofElement

sealed trait AVLProofElement extends TwoPartyProofElement

sealed trait SLTProofElement extends TwoPartyProofElement

case class ProofLevel(e: Level) extends WTProofElement with AVLProofElement with SLTProofElement{
  val bytes: Array[Byte] = e.bytes
}

trait ProofLabel extends WTProofElement with AVLProofElement with SLTProofElement {
  val e: Array[Byte]
  val bytes: Array[Byte] = e

  override def toString: String = s"WTProofKey(${Base58.encode(e).take(8)})"
}

case class ProofRightLabel(e: Array[Byte]) extends ProofLabel

case class ProofLeftLabel(e: Array[Byte]) extends ProofLabel

trait Key extends WTProofElement with AVLProofElement with SLTProofElement {
  val e: Array[Byte]
  val bytes: Array[Byte] = e

  override def toString: String = s"Key(${Base58.encode(e).take(8)})"
}

case class ProofKey(e: Array[Byte]) extends Key

case class ProofNextLeafKey(e: Array[Byte]) extends Key

case class ProofValue(e: Array[Byte]) extends WTProofElement with AVLProofElement with SLTProofElement {
  val bytes: Array[Byte] = e

  override def toString: String = s"WTProofKey(${Base58.encode(e).take(8)})"
}

case class ProofDirection(direction: Direction) extends WTProofElement with AVLProofElement {
  override val bytes: Array[Byte] = Array(direction match {
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

// TODO: change Level to Balance and make this better
case class ProofBalance(e: Int) extends AVLProofElement {
  override val bytes: Array[Byte] = Array(e match {
    case -1 => 0: Byte
    case 0 => 1: Byte
    case 1 => 2: Byte
  })
}