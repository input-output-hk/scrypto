package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.ProverNodes
import scorex.crypto.hash.Digest


/**
  * Top subtree of AVL tree, starting from root node and ending with ProxyInternalNode
  */
case class BatchAVLProverManifest[D <: Digest](root: ProverNodes[D],
                                               rootHeight: Int) {
  def verify: Boolean = {
    true
  }
}
