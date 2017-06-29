package scorex.crypto.authds.merkle

import scorex.crypto.hash.CommutativeHash

import scala.annotation.tailrec
import scala.collection.mutable

case class MerkleTree(topNode: InternalNode,
                      elementsHashIndexes: Map[mutable.WrappedArray.ofByte, Int]) {

  lazy val rootHash: Array[Byte] = topNode.hash
  lazy val length: Int = elementsHashIndexes.size


  def proofByElement(element: Leaf): Option[MerkleProof] = proofByElementHash(element.hash)

  def proofByElementHash(hash: Array[Byte]): Option[MerkleProof] = {
    elementsHashIndexes.get(new mutable.WrappedArray.ofByte(hash)).flatMap(i => proofByIndex(i))
  }

  def proofByIndex(index: Int): Option[MerkleProof] = {
    def loop(node: Node, i: Int, curLength: Int, acc: Seq[Node]): Option[(Leaf, Seq[Node])] = {
      node match {
        case n: InternalNode if i < curLength / 2 =>
          loop(n.left, i, curLength / 2, acc :+ n.right)
        case n: InternalNode if i < curLength =>
          loop(n.right, i - curLength / 2, curLength / 2, acc :+ n.left)
        case n: Leaf =>
          Some((n, acc.filter(n => n != EmptyNode).reverse))
        case _ =>
          None
      }
    }
    val leafWithProofs = loop(topNode, index, lengthWithEmptyLeafs, Seq())
    leafWithProofs.map(lp => MerkleProof(lp._1, lp._2.map(_.hash)))
  }

  lazy val lengthWithEmptyLeafs = {
    def log2(x: Double): Double = math.log(x) / math.log(2)
    Math.max(math.pow(2, math.ceil(log2(length))).toInt, 2)
  }

  //Debug only
  override lazy val toString: String = {
    def loop(nodes: Seq[Node], acc: String): String = {
      if (nodes.nonEmpty) {
        val thisLevStr = nodes.map(_.toString).mkString(",") + "\n"
        val nextLevNodes = nodes.flatMap {
          case i: InternalNode => Seq(i.left, i.right)
          case _ => Seq()
        }
        loop(nextLevNodes, acc + thisLevStr)
      } else {
        acc
      }
    }
    loop(Seq(topNode), "")
  }
}

object MerkleTree {

  def apply(payload: Seq[Array[Byte]])
           (implicit hf: CommutativeHash[_]): MerkleTree = {
    val leafs = payload.map(d => Leaf(d))
    val elementsIndex: Map[mutable.WrappedArray.ofByte, Int] = leafs.indices.map { i =>
      (new mutable.WrappedArray.ofByte(leafs(i).hash), i)
    }.toMap
    val topNode = calcTopNode(leafs)

    MerkleTree(topNode, elementsIndex)
  }

  @tailrec
  def calcTopNode(nodes: Seq[Node])(implicit hf: CommutativeHash[_]): InternalNode = {
    val nextNodes = nodes.grouped(2).map(lr => InternalNode(lr.head, if (lr.length == 2) lr.last else EmptyNode)).toSeq
    if (nextNodes.length == 1) nextNodes.head
    else calcTopNode(nextNodes)
  }

}
