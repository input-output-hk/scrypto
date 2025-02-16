package scorex.crypto.authds.merkle

import scorex.crypto.authds.merkle.MerkleTree.InternalNodePrefix
import scorex.crypto.authds.{LeafData, Side}
import scorex.crypto.hash.{Digest, _}

import scala.annotation.tailrec
import scala.collection.mutable

case class MerkleTree[D <: Digest](topNode: Node[D],
                                   elementsHashIndex: Map[mutable.WrappedArray.ofByte, Int]) {

  lazy val rootHash: D = topNode.hash
  lazy val length: Int = elementsHashIndex.size

  def proofByElement(element: Leaf[D]): Option[MerkleProof[D]] = proofByElementHash(element.hash)

  def proofByElementHash(hash: D): Option[MerkleProof[D]] = {
    elementsHashIndex.get(new mutable.WrappedArray.ofByte(hash)).flatMap(i => proofByIndex(i))
  }

  def proofByIndex(index: Int): Option[MerkleProof[D]] = if (index >= 0 && index < length) {
    def loop(node: Node[D], i: Int, curLength: Int, acc: Seq[(D, Side)]): Option[(Leaf[D], Seq[(D, Side)])] = {
      node match {
        case n: InternalNode[D] if i < curLength / 2 =>
          loop(n.left, i, curLength / 2, acc :+ (n.right.hash, MerkleProof.LeftSide))
        case n: InternalNode[D] if i < curLength =>
          loop(n.right, i - curLength / 2, curLength / 2, acc :+ (n.left.hash, MerkleProof.RightSide))
        case n: Leaf[D] =>
          Some((n, acc.reverse))
        case _ =>
          None
      }
    }

    val leafWithProofs = loop(topNode, index, lengthWithEmptyLeafs, Seq())
    leafWithProofs.map(lp => MerkleProof(lp._1.data, lp._2)(lp._1.hf))
  } else {
    None
  }

  /**
    * Build compact batch Merkle proof by indices
    *
    * @param indices - leaf indices
    * @return Optional BatchMerkleProof
    */
  def proofByIndices(indices: Seq[Int])(implicit hf: CryptographicHash[D]): Option[BatchMerkleProof[D]] = {

    /**
      * Recursive function to build the multiproof
      *
      * @param a - leaf indices
      * @param l - hashes of the current layer of the Merkle tree
      * @return multiproof as sequence of pairs (hash, side)
      */

    def loop(a: Seq[Int], l: Seq[Digest]): Seq[(Digest, Side)] = {

      // For each of the indices in A, take the index of its immediate neighbor in layer L
      // Store the given element index and the neighboring index as a pair of indices
      // Remove any duplicates
      val b_pruned = a
        .map(i => {
          if (i % 2 == 0) {
            (i, i + 1)
          } else {
            (i - 1, i)
          }
        })
        .distinct

      // Take the difference between the set of indices in B_pruned and A
      // Append the hash values (and side) for the given indices in the current Merkle layer to the multiproof M
      val b_flat = b_pruned.flatten{case (a,b) => Seq(a,b)}
      val dif = b_flat diff a
      var m = dif.map(i => {
        val side = if (i % 2 == 0) MerkleProof.LeftSide else MerkleProof.RightSide
        (l.lift(i).getOrElse(EmptyNode[D]().hash), side)
      })

      //  Take all the even numbers from B_pruned, and divide them by two
      val a_new = b_pruned.map(_._1 / 2)

      //  Go up one layer in the tree
      val l_new = l.grouped(2).map(lr => {
        hf.prefixedHash(InternalNodePrefix,
          lr.head, if (lr.lengthCompare(2) == 0) lr.last else EmptyNode[D]().hash)
      }).toSeq

      //  Repeat until the root of the tree is reached
      if (l_new.size > 1) {
        m = m ++ loop(a_new, l_new)
      }
      m
    }

    if (indices.nonEmpty && indices.forall(index => index >= 0 && index < length)) {
      val hashes: Seq[Digest] = elementsHashIndex.toSeq.sortBy(_._2).map(_._1.toArray.asInstanceOf[Digest])
      val normalized_indices = indices.distinct.sorted
      val multiproof = loop(normalized_indices, hashes)
      Some(BatchMerkleProof(normalized_indices zip (normalized_indices map hashes.apply), multiproof))
    } else {
      None
    }
  }

  lazy val lengthWithEmptyLeafs: Int = {
    def log2(x: Double): Double = math.log(x) / math.log(2)

    Math.max(math.pow(2, math.ceil(log2(length))).toInt, 2)
  }

  //Debug only
  override lazy val toString: String = {
    def loop(nodes: Seq[Node[D]], level: Int, acc: String): String = {
      if (nodes.nonEmpty) {
        val thisLevStr = s"Level $level: " + nodes.map(_.hash.toList).map(_.toString).mkString(",") + "\n"
        val nextLevNodes = nodes.flatMap {
          case i: InternalNode[D] => Seq(i.left, i.right)
          case _ => Seq()
        }
        loop(nextLevNodes, level + 1, acc + thisLevStr)
      } else {
        acc
      }
    }

    loop(Seq(topNode), 0, "")
  }
}

object MerkleTree {
  val LeafPrefix: Byte = 0: Byte
  val InternalNodePrefix: Byte = 1: Byte

  /**
    * Construct Merkle tree from leafs
    *
    * @param payload       - sequence of leafs data
    * @param hf            - hash function
    * @tparam D - hash function application type
    * @return MerkleTree constructed from current leafs with defined empty node and hash function
    */
  def apply[D <: Digest](payload: Seq[LeafData])
                        (implicit hf: CryptographicHash[D]): MerkleTree[D] = {
    val leafs = payload.map(d => Leaf(d))
    val elementsIndex: Map[mutable.WrappedArray.ofByte, Int] = leafs.indices.map { i =>
      (new mutable.WrappedArray.ofByte(leafs(i).hash), i)
    }.toMap
    val topNode = calcTopNode[D](leafs)

    MerkleTree(topNode, elementsIndex)
  }

  @tailrec
  def calcTopNode[D <: Digest](nodes: Seq[Node[D]])(implicit hf: CryptographicHash[D]): Node[D] = {
    if (nodes.isEmpty) {
      EmptyRootNode[D]()
    } else {
      val nextNodes = nodes.grouped(2)
        .map(lr => InternalNode[D](lr.head, if (lr.lengthCompare(2) == 0) lr.last else EmptyNode[D]())).toSeq
      if (nextNodes.lengthCompare(1) == 0) nextNodes.head else calcTopNode(nextNodes)
    }
  }
}
