package scorex.crypto.authds.merkle

import scorex.crypto.authds.{LeafData, Side}
import scorex.crypto.hash._

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

  lazy val lengthWithEmptyLeafs: Int = {
    def log2(x: Double): Double = math.log(x) / math.log(2)

    Math.max(math.pow(2, math.ceil(log2(length))).toInt, 2)
  }

  //Debug only
  override lazy val toString: String = {
    def loop(nodes: Seq[Node[D]], level: Int, acc: String): String = {
      if (nodes.nonEmpty) {
        val thisLevStr = s"Level $level: " + nodes.map(_.toString).mkString(",") + "\n"
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
      EmptyRootNode[D]
    } else {
      val nextNodes = nodes.grouped(2)
        .map(lr => InternalNode[D](lr.head, if (lr.lengthCompare(2) == 0) lr.last else EmptyNode[D])).toSeq
      if (nextNodes.lengthCompare(1) == 0) nextNodes.head else calcTopNode(nextNodes)
    }
  }
}
