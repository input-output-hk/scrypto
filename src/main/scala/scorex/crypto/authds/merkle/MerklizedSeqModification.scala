package scorex.crypto.authds.merkle

import scorex.crypto.authds.merkle.MerkleTree.Position

sealed trait MerklizedSeqModification

final case class MerklizedSeqAppend(element: Array[Byte]) extends MerklizedSeqModification

final case class MerklizedSeqRemoval(position: Position) extends MerklizedSeqModification
