package scorex.crypto.authds


trait TwoPartyProof[Key, Value] {
  type Label = Array[Byte]
  val key: Key
  val proofSeq: Seq[TwoPartyProofElement]
  def verify(digest: Label, updateFunction: Option[Value] => Value, toInsertIfNotFound: Boolean = true): Option[Label]
}
