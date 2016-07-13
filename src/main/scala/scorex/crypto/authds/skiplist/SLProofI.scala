package scorex.crypto.authds.skiplist

import scorex.crypto.authds.AuthData
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

trait SLProofI extends AuthData[SLPath] {
  type Digest = CryptographicHash#Digest

  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean

  def bytes: Array[Byte]

  /**
   * Returns false if the element is in skiplist, true otherwise.
   */
  def isEmpty: Boolean

  /**
   * Returns true if the element is in skiplist, false otherwise.
   */
  def isDefined: Boolean = !isEmpty
}
