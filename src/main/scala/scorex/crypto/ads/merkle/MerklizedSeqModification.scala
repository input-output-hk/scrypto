package scorex.crypto.ads.merkle

sealed trait MerklizedSeqModification {
  val position: Position
}

final case class MerklizedSeqAppend(override val position: Position, element: Array[Byte]) extends MerklizedSeqModification

final case class MerklizedSeqRemoval(override val position: Position) extends MerklizedSeqModification
