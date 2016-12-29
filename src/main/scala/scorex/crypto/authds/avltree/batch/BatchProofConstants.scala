package scorex.crypto.authds.avltree.batch

/**
  * Created by kushti on 29.12.16.
  */
trait BatchProofConstants {
  // Do not use bytes -1, 0, or 1 -- these are for balance
  val LeafInPackagedProof: Byte = 2
  val LabelInPackagedProof: Byte = 3
  val EndOfTreeInPackagedProof: Byte = 4
}
