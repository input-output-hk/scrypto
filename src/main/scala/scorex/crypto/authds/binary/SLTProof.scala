package scorex.crypto.authds.binary

import scala.collection.mutable

case class SLTProof(proof: mutable.Queue[SLTProofElement])

sealed trait SLTProofElement

case class SLTProofLevel(e: Int) extends SLTProofElement

case class SLTProofRightLabel(e: Array[Byte]) extends SLTProofElement

case class SLTProofLeftLabel(e: Array[Byte]) extends SLTProofElement

case class SLTProofKey(e: SLTKey) extends SLTProofElement

case class SLTProofValue(e: SLTValue) extends SLTProofElement
