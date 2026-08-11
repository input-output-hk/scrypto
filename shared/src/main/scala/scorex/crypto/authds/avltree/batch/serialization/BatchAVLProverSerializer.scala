package scorex.crypto.authds.avltree.batch.serialization

import scorex.crypto.authds.avltree.batch.{BatchAVLProver, InternalProverNode, ProverLeaf, ProverNodes}
import scorex.crypto.authds.{ADKey, ADValue, Balance}
import scorex.crypto.hash.{CryptographicHash, Digest}
import scorex.util.encode.Base16
import scorex.utils.{ByteArray, Bytes, Ints, Logger}

import scala.annotation.tailrec
import scala.collection.mutable.ArrayBuffer
import scala.util.Try

/**
  * Serializes and deserializes a [[BatchAVLProver]] tree into a manifest and subtrees.
  * The binary format is self-describing and includes length prefixes for variable-size subtrees.
  * Deserialization rejects malformed or inconsistent input by returning `Failure`.
  */
class BatchAVLProverSerializer[D <: Digest, HF <: CryptographicHash[D]]
    (implicit val hf: HF, val logger: Logger) { serializer =>

  private val labelLength = hf.DigestSize

  type SlicedTree = (BatchAVLProverManifest[D], scala.collection.Seq[BatchAVLProverSubtree[D]])

  /**
    * Slices an AVL tree into a top manifest and bottom subtrees at the given `subtreeDepth`.
    */
  def slice(tree: BatchAVLProver[D, HF], subtreeDepth: Int): SlicedTree = tree.topNode match {
    case tn: InternalProverNode[D] =>

      val height = tree.rootNodeHeight
      val rootProxyNode = ProxyInternalNode(tn)
      val subtrees = ArrayBuffer.empty[BatchAVLProverSubtree[D]]

      def getSubtrees(currentNode: ProverNodes[D],
                      currentHeight: Int,
                      parent: ProxyInternalNode[D]): Unit = {
        currentNode match {
          case n: InternalProverNode[D] if currentHeight > subtreeDepth =>
            val nextParent = ProxyInternalNode(n)
            parent.setChild(nextParent)
            getSubtrees(n.left, currentHeight - 1, nextParent)
            getSubtrees(n.right, currentHeight - 1, nextParent)
          case n: InternalProverNode[D] =>
            parent.setChild(ProxyInternalNode(n))
            subtrees += BatchAVLProverSubtree(n.left)
            subtrees += BatchAVLProverSubtree(n.right)
          case l: ProverLeaf[D] =>
            parent.setChild(l)
            subtrees += BatchAVLProverSubtree(l)
        }
      }

      getSubtrees(tn.left, height - 1, rootProxyNode)
      getSubtrees(tn.right, height - 1, rootProxyNode)
      val manifest = BatchAVLProverManifest[D](rootProxyNode, height)
      (manifest, subtrees)
    case l: ProverLeaf[D] =>
      (BatchAVLProverManifest[D](l, tree.rootNodeHeight), Seq.empty[BatchAVLProverSubtree[D]])
  }

  /**
    * Combines a manifest and its subtrees back into a single prover tree.
    */
  def combine(sliced: SlicedTree,
              keyLength: Int,
              valueLengthOpt: Option[Int]): Try[BatchAVLProver[D, HF]] = Try {
    val manifest = sliced._1
    // Subtree lookups need O(1) indexed access. Array-backed inputs (including the ArrayBuffer
    // produced by `slice`) are used as-is, without copying; linear sequences are copied once.
    val subtrees: scala.collection.IndexedSeq[BatchAVLProverSubtree[D]] = sliced._2 match {
      case iseq: scala.collection.IndexedSeq[BatchAVLProverSubtree[D]] @unchecked => iseq
      case other => ArrayBuffer.empty[BatchAVLProverSubtree[D]] ++= other
    }

    // Sort subtree indices by digest once. This gives O(log n) lookups without storing the
    // subtrees twice in a digest-keyed map.
    val sortedIndices = subtrees.indices.toArray.sortWith { (i, j) =>
      ByteArray.compare(subtrees(i).id, subtrees(j).id) < 0
    }

    // Reject duplicate subtree ids.
    var k = 0
    while (k < sortedIndices.length - 1) {
      require(
        !subtrees(sortedIndices(k)).id.sameElements(subtrees(sortedIndices(k + 1)).id),
        "duplicate subtree id"
      )
      k += 1
    }

    val used = new Array[Boolean](subtrees.length)

    // Binary search for a subtree with the given digest label.
    def findSubtree(label: D): Option[Int] = {
      var lo = 0
      var hi = sortedIndices.length
      while (lo < hi) {
        val mid = (lo + hi) >>> 1
        val cmp = ByteArray.compare(subtrees(sortedIndices(mid)).id, label)
        if (cmp == 0) return Some(sortedIndices(mid))
        else if (cmp < 0) lo = mid + 1
        else hi = mid
      }
      None
    }

    manifest.root match {
      case tn: InternalProverNode[D] =>

        // manifest being mutated here
        def mutateLoop(n: ProverNodes[D], depth: Int): Unit = {
          require(depth >= 0, "tree depth exceeds maximum allowed depth")
          n match {
            case n: ProxyInternalNode[D] if n.isEmpty =>
              val left = findSubtree(n.leftLabel) match {
                case Some(idx) if !used(idx) =>
                  used(idx) = true
                  subtrees(idx).subtreeTop
                case Some(_) => throw new IllegalArgumentException("duplicate subtree reference")
                case None => throw new IllegalArgumentException("missing left subtree")
              }
              val right = findSubtree(n.rightLabel) match {
                case Some(idx) if !used(idx) =>
                  used(idx) = true
                  subtrees(idx).subtreeTop
                case Some(_) => throw new IllegalArgumentException("duplicate subtree reference")
                case None => throw new IllegalArgumentException("missing right subtree")
              }
              n.setChild(left)
              n.setChild(right)
            case n: InternalProverNode[D] =>
              mutateLoop(n.left, depth - 1)
              mutateLoop(n.right, depth - 1)
            case _ =>
          }
        }

        mutateLoop(tn, manifest.rootHeight)
      case _: ProverLeaf[D] =>
    }

    require(used.forall(identity), "unused subtrees")

    // Compute the actual height of the combined tree and verify it matches the manifest height.
    // This prevents a manifest from claiming an arbitrary height that the BatchAVLProver constructor
    // would otherwise accept verbatim.
    def treeHeight(node: ProverNodes[D]): Int = {
      var stack = List((node, 0))
      var maxHeight = 0
      while (stack.nonEmpty) {
        val (n, depth) = stack.head
        stack = stack.tail
        n match {
          case _: ProverLeaf[D] =>
            maxHeight = math.max(maxHeight, depth)
          case pn: ProxyInternalNode[D] if pn.isEmpty =>
            throw new IllegalStateException("unfilled proxy node in combined tree")
          case in: InternalProverNode[D] =>
            stack = (in.left, depth + 1) :: (in.right, depth + 1) :: stack
          case _ =>
            throw new IllegalStateException("unexpected node type")
        }
      }
      maxHeight
    }
    val actualHeight = treeHeight(manifest.root)
    require(actualHeight == manifest.rootHeight,
      s"manifest height ${manifest.rootHeight} does not match actual tree height $actualHeight")

    new BatchAVLProver[D, HF](keyLength, valueLengthOpt, Some(manifest.root -> manifest.rootHeight)) {
      override val logger = serializer.logger
    }
  }

  /**
    * Serializes a manifest to bytes: root height followed by the serialized root node.
    */
  def manifestToBytes(manifest: BatchAVLProverManifest[D]): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(manifest.rootHeight),
      nodesToBytes(manifest.root)
    )
  }

  /**
    * Deserializes a manifest from bytes.
    * Validates the root height and encoded node structure.
    */
  def manifestFromBytes(bytes: Array[Byte],
                        keyLength: Int): Try[BatchAVLProverManifest[D]] = Try {
    val oldHeight = Ints.fromByteArray(bytes.slice(0, 4))
    require(oldHeight >= 0 && oldHeight < 256, "manifest height must be in range 0..255")
    val oldTop = nodesFromBytes(bytes.slice(4, bytes.length), keyLength, oldHeight).get
    BatchAVLProverManifest[D](oldTop, oldHeight)
  }

  /**
    * Serializes a subtree to bytes.
    */
  def subtreeToBytes(t: BatchAVLProverSubtree[D]): Array[Byte] = nodesToBytes(t.subtreeTop)

  /**
    * Deserializes a subtree from bytes.
    * Validates the encoded node structure.
    */
  def subtreeFromBytes(b: Array[Byte], kl: Int): Try[BatchAVLProverSubtree[D]] = {
    nodesFromBytes(b, kl, maxDepth = 255).
      map(topNode => BatchAVLProverSubtree[D](topNode))
  }

  /**
    * Deserializes a tree node and its descendants from bytes.
    * Validates the encoded structure and subtree lengths.
    * Uses offset/end bounds instead of recursive slicing to avoid quadratic copying.
    */
  def nodesFromBytes(bytesIn: Array[Byte], keyLength: Int, maxDepth: Int = 255): Try[ProverNodes[D]] = Try {
    require(keyLength > 0)
    require(maxDepth >= 0, "maxDepth must be non-negative")

    def parse(start: Int, end: Int, depth: Int): (ProverNodes[D], Int) = {
      require(depth >= 0, "serialized tree depth exceeds maximum allowed depth")
      require(start < end, "empty node bytes")
      bytesIn(start) match {
        case 0 =>
          require(start + 1L + 2L * keyLength <= end, "truncated leaf bytes")
          val key = ADKey @@ bytesIn.slice(start + 1, start + 1 + keyLength)
          val nextLeafKey = ADKey @@ bytesIn.slice(start + 1 + keyLength, start + 1 + 2 * keyLength)
          val value = ADValue @@ bytesIn.slice(start + 1 + 2 * keyLength, end)
          (new ProverLeaf[D](key, value, nextLeafKey), end)
        case 1 =>
          require(start + 2 + keyLength <= end, "truncated internal node header")
          val balance = Balance @@ bytesIn(start + 1)
          require(balance >= -1 && balance <= 1, s"invalid balance value: $balance")
          val key = ADKey @@ bytesIn.slice(start + 2, start + 2 + keyLength)
          require(start + keyLength + 6 <= end, "truncated internal node leftLength")
          val leftLength = Ints.fromBytes(
            bytesIn(start + keyLength + 2),
            bytesIn(start + keyLength + 3),
            bytesIn(start + keyLength + 4),
            bytesIn(start + keyLength + 5)
          )
          require(leftLength > 0, "left subtree length must be positive")
          val leftEndLong = start.toLong + keyLength.toLong + 6L + leftLength.toLong
          require(leftEndLong < end.toLong, "left subtree length leaves no bytes for right subtree")
          require(leftEndLong <= Int.MaxValue, "left subtree length too large")
          val leftEnd = leftEndLong.toInt
          val (left, leftConsumedEnd) = parse(start + keyLength + 6, leftEnd, depth - 1)
          require(leftConsumedEnd == leftEnd, s"left subtree did not consume exactly $leftLength bytes")
          val (right, rightEnd) = parse(leftEnd, end, depth - 1)
          require(rightEnd == end, "right subtree does not consume remaining bytes")

          // check that left.key < key <= right.key
          val leftComparison = ByteArray.compare(left.key, key)
          val rightComparison = ByteArray.compare(key, right.key)
          require(leftComparison < 0 && rightComparison <= 0, s"key check fail for key ${Base16.encode(key)}")
          (new InternalProverNode[D](key, left, right, balance), end)
        case 2 =>
          val nodeEnd = start + 2 + keyLength + 2 * labelLength
          require(nodeEnd == end, "proxy node length mismatch")
          val balance = Balance @@ bytesIn(start + 1)
          require(balance >= -1 && balance <= 1, s"invalid balance value: $balance")
          val key = ADKey @@ bytesIn.slice(start + 2, start + 2 + keyLength)
          val leftLabel = hf.byteArrayToDigest(bytesIn.slice(start + keyLength + 2, start + keyLength + 2 + labelLength)).get
          val rightLabel = hf.byteArrayToDigest(bytesIn.slice(start + keyLength + 2 + labelLength, nodeEnd)).get
          (new ProxyInternalNode[D](key, leftLabel, rightLabel, balance), nodeEnd)
        case tag =>
          throw new IllegalArgumentException(s"unknown node tag: $tag")
      }
    }

    val (node, end) = parse(0, bytesIn.length, maxDepth)
    require(end == bytesIn.length, "trailing bytes after serialized node")
    node
  }

  /**
    * Serializes a tree node and its descendants to bytes.
    */
  def nodesToBytes(rootNode: ProverNodes[D]): Array[Byte] = {
    def loop(currentNode: ProverNodes[D]): Array[Byte] = currentNode match {
      case l: ProverLeaf[D] =>
        Bytes.concat(Array(0.toByte), l.key, l.nextLeafKey, l.value)
      case n: ProxyInternalNode[D] if n.isEmpty =>
        Bytes.concat(Array(2.toByte, n.balance), n.key, n.leftLabel, n.rightLabel)
      case n: InternalProverNode[D] =>
        val leftBytes = loop(n.left)
        val rightBytes = loop(n.right)
        Bytes.concat(Array(1.toByte, n.balance), n.key, Ints.toByteArray(leftBytes.length), leftBytes, rightBytes)
    }

    loop(rootNode)
  }
}

