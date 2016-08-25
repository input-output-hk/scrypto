package scorex.crypto.authds.sltree

import com.google.common.primitives.Ints
import scorex.crypto.encode.Base58

sealed trait SLTProofElement {
  val bytes: Array[Byte]
}

case class SLTProofLevel(e: Int) extends SLTProofElement {
  val bytes: Array[Byte] = Ints.toByteArray(e)
}

trait SLTProofLabel extends SLTProofElement {
  val e: Array[Byte]
  val bytes: Array[Byte] = e

  override def toString: String = s"SLTProofKey(${Base58.encode(e).take(8)})"
}

case class SLTProofRightLabel(e: Array[Byte]) extends SLTProofLabel

case class SLTProofLeftLabel(e: Array[Byte]) extends SLTProofLabel

case class SLTProofKey(e: SLTKey) extends SLTProofElement {
  val bytes: Array[Byte] = e
  override def toString: String = s"SLTProofKey(${Base58.encode(e).take(8)})"
}

case class SLTProofValue(e: SLTValue) extends SLTProofElement {
  val bytes: Array[Byte] = e
  override def toString: String = s"SLTProofKey(${Base58.encode(e).take(8)})"
}