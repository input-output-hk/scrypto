package scorex.crypto.authds.binary

import scorex.crypto.encode.Base58

sealed trait SLTProofElement

case class SLTProofLevel(e: Int) extends SLTProofElement

trait SLTProofLabel extends SLTProofElement {
  val e: Array[Byte]

  override def toString: String = s"SLTProofKey(${Base58.encode(e).take(8)})"
}

case class SLTProofRightLabel(e: Array[Byte]) extends SLTProofLabel

case class SLTProofLeftLabel(e: Array[Byte]) extends SLTProofLabel

case class SLTProofKey(e: SLTKey) extends SLTProofElement {
  override def toString: String = s"SLTProofKey(${Base58.encode(e).take(8)})"
}

case class SLTProofValue(e: SLTValue) extends SLTProofElement {
  override def toString: String = s"SLTProofKey(${Base58.encode(e).take(8)})"
}