package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.ProverNodes
import scorex.crypto.hash.{CryptographicHash, Digest}

import scala.util.Try

/**
  * Top subtree of AVL tree, starting from root node and ending with FinalInternalNode
  */
case class BatchAVLProverManifest[D <: Digest, HF <: CryptographicHash[D]](keyLength: Int,
                                                                           valueLengthOpt: Option[Int],
                                                                           oldRootAndHeight: (ProverNodes[D], Int))
