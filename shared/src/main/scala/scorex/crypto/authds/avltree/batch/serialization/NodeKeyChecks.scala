package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.ADKey
import scorex.crypto.authds.avltree.batch.{InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.hash.Digest
import scorex.util.encode.Base16
import scorex.utils.ByteArray

import scala.annotation.tailrec
import scala.collection.mutable
import scala.util.Try

/**
  * Keys of internal nodes are not committed to by node labels: `InternalNode.computeLabel` hashes the
  * balance and the two children labels, and nothing else. A manifest or a subtree therefore carries keys
  * which its own digest does not authenticate, so a verifier checking labels alone takes them on trust.
  *
  * They do not have to be trusted, because they are fully determined by the leaves: the key of an internal
  * node is the smallest key of its right subtree. That is the invariant `BatchAVLProver.checkTree` enforces
  * ("min of right subtree doesn't match"), and it lets a received subtree be checked against itself.
  */
private[serialization] object NodeKeyChecks {

  /**
    * Smallest key of the subtree rooted at `node`, checking on the way up that every internal node carries
    * the key its right subtree implies.
    *
    * Requires the subtree to be materialized: a [[ProxyInternalNode]] whose children are still labels
    * cannot be descended into, and is rejected rather than skipped.
    */
  private def checkedMinKey[D <: Digest](node: ProverNodes[D]): ADKey = node match {
    case l: ProverLeaf[D] =>
      l.key
    case n: ProxyInternalNode[D] if n.isEmpty =>
      throw new IllegalArgumentException(
        s"Node ${Base16.encode(n.label)} still has unresolved children, its keys cannot be checked")
    case n: InternalProverNode[D] =>
      val minLeft = checkedMinKey(n.left)
      val minRight = checkedMinKey(n.right)
      if (ByteArray.compare(n.key, minRight) != 0) {
        throw new IllegalArgumentException(
          s"Key ${Base16.encode(n.key)} of internal node ${Base16.encode(n.label)} does not match " +
            s"the smallest key of its right subtree, ${Base16.encode(minRight)}")
      }
      minLeft
  }

  /**
    * Whether every internal node of a materialized subtree carries the key its leaves imply.
    *
    * Complete: a subtree passing this check cannot contain a forged internal key.
    */
  def keysAreConsistent[D <: Digest](node: ProverNodes[D]): Boolean = checkKeys(node).isSuccess

  /** As [[keysAreConsistent]], but keeps the reason so callers can report it */
  def checkKeys[D <: Digest](node: ProverNodes[D]): Try[Unit] = Try(checkedMinKey(node)).map(_ => ())

  /**
    * Whether the internal node keys of a manifest are strictly increasing in in-order traversal.
    *
    * A manifest ends at [[ProxyInternalNode]]s whose children are only labels, so the keys below them are
    * not available and [[keysAreConsistent]] cannot be used. What can still be checked is the search-tree
    * ordering: with every internal key being the smallest key of its right subtree, an in-order walk of the
    * internal nodes yields strictly increasing keys, the terminal proxy nodes included. This is the check
    * available "assuming bottom keys of subtrees are correct"; the complete one runs once the subtrees are
    * attached, in `BatchAVLProverSerializer.combine`.
    */
  def keysAreOrdered[D <: Digest](root: ProverNodes[D]): Boolean = {
    val keys = mutable.Buffer.empty[ADKey]

    def inOrder(node: ProverNodes[D]): Unit = node match {
      case _: ProverLeaf[D] =>
      case n: ProxyInternalNode[D] if n.isEmpty =>
        keys += n.key
      case n: InternalProverNode[D] =>
        inOrder(n.left)
        keys += n.key
        inOrder(n.right)
    }

    inOrder(root)

    @tailrec
    def strictlyIncreasing(i: Int): Boolean = {
      if (i >= keys.length) true
      else if (ByteArray.compare(keys(i - 1), keys(i)) >= 0) false
      else strictlyIncreasing(i + 1)
    }

    strictlyIncreasing(1)
  }

}
