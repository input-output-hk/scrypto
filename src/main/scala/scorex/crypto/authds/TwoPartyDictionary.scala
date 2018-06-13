package scorex.crypto.authds

import scorex.crypto.authds.avltree.batch.Operation
import scorex.utils.ScorexEncoding

import scala.util.Try

trait TwoPartyDictionary extends ScorexEncoding {

  /**
    * Run an operation, whether a lookup or a modification, against the tree
    *
    * @param operation - tree modification
    * @return modification proof
    */
  def run[O <: Operation](operation: O): Try[TwoPartyProof]

  /**
    * @return current digest of structure
    */
  def rootHash(): ADDigest
}
