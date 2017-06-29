package scorex.crypto.authds.merkle

import scorex.crypto.hash.{CommutativeHash, ThreadUnsafeHash}

import scala.annotation.tailrec

case class MerkleTree(topNode: InternalNode, length: Int) {

  lazy val rootHash: Array[Byte] = topNode.hash

  def proofByIndex(index: Int): Option[MerkleProof] = {
    def loop(node: Node, i: Int, curLength: Int, acc: Seq[Node]): Option[(Leaf, Seq[Node])] = {
      node match {
        case n: InternalNode if i < curLength / 2 =>
          loop(n.left, i, curLength / 2, acc :+ n.right)
        case n: InternalNode if i < curLength =>
          loop(n.right, i - curLength / 2, curLength / 2, acc :+ n.left)
        case n: Leaf =>
          Some((n, acc))
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
}

object MerkleTree {

  def apply(payload: Seq[Array[Byte]])
           (implicit hf: CommutativeHash[_]): MerkleTree = {
    val leafs = payload.map(d => Leaf(d))
    val topNode = calcTopNode(leafs)

    MerkleTree(topNode, leafs.length)
  }

  @tailrec
  def calcTopNode(nodes: Seq[Node])(implicit hf: CommutativeHash[_]): InternalNode = {
    val nextNodes = nodes.grouped(2).map(lr => InternalNode(lr.head, if (lr.length == 2) lr.last else EmptyNode)).toSeq
    if (nextNodes.length == 1) nextNodes.head
    else calcTopNode(nextNodes)
  }

}
