package scorex.crypto.authds.merkle

import scorex.crypto.hash.ThreadUnsafeHash

import scala.annotation.tailrec

case class MerkleTree(topNode: InternalNode) {


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
  def calcTopNode(nodes: Seq[Node])(implicit hf: ThreadUnsafeHash): InternalNode =  {
    val nextNodes = nodes.grouped(2).map(lr => InternalNode(lr.head, if(lr.length == 2) lr.last else EmptyNode)).toSeq
    if(nextNodes.length == 1) nextNodes.head
    else calcTopNode(nextNodes)
  }

}
