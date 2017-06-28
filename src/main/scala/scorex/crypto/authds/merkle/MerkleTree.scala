package scorex.crypto.authds.merkle

import scorex.crypto.hash.ThreadUnsafeHash

import scala.annotation.tailrec

case class MerkleTree(topNode: Node) {


  lazy val rootHash:Array[Byte] = topNode.hash

}

object MerkleTree {

  def apply(payload: Seq[Array[Byte]])
           (implicit hf: ThreadUnsafeHash): MerkleTree = {
    val leafs = payload.map(d => Leaf(d))
    val topNode = calcTopNode(leafs)

    MerkleTree(topNode)
  }

  @tailrec
  def calcTopNode(nodes: Seq[Node])(implicit hf: ThreadUnsafeHash): Node = if (nodes.length == 1) {
    nodes.head
  } else {
    calcTopNode(nodes.grouped(2).map(lr => InternalNode(lr.head, lr.lastOption.getOrElse(EmptyNode))).toSeq)
  }

}
