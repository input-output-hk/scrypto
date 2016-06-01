package scorex.crypto.authds.skiplist

import scorex.crypto.authds.skiplist.SkipList.{NodeValue, NodeKey, SLValue, SLKey}
import scorex.crypto.authds.storage.{StorageType, KVStorage}
import scorex.crypto.encode.Base64
import scorex.crypto.hash.CommutativeHash

import scala.annotation.tailrec
import scala.util.Random

class SkipList[HF <: CommutativeHash[_]](implicit hf: HF) {

  //top left node
  var topNode: SLNode = SLNode(MinSLElement, Some(SLNode(MaxSLElement, None, None, 0, true).nodeKey), None, 0, true)

  private def leftAt(l: Int): Option[SLNode] = {
    require(l <= topNode.level)
    topNode.downUntil(_.level == l)
  }

  def contains(e: SLElement): Boolean = find(e).isDefined

  def elementProof(e: SLElement): Option[SLAuthData] = find(e).map { n =>
    SLAuthData(e.bytes, SLPath(topNode.hashTrack(e)))
  }

  // find bottom node with current element
  def find(e: SLElement): Option[SLNode] = {
    @tailrec
    def loop(node: SLNode): Option[SLNode] = {
      val prevNodeOpt = node.rightUntil(n => n.right.exists(rn => rn.el > e))
      require(prevNodeOpt.isDefined, "Non-infinite element should have right node")
      val prevNode = prevNodeOpt.get
      prevNode.down match {
        case Some(dn) => loop(dn)
        case _ => if (prevNode.el == e) Some(node) else None
      }
    }
    loop(topNode)
  }

  def insert(e: SLElement): Boolean = if (contains(e)) {
    false
  } else {
    val eLevel = selectLevel(e)
    if (eLevel == topNode.level) newTopLevel()
    def insertOne(lev: Int, down: Option[SLNode]): Unit = if (lev <= eLevel) {
      val startNode: SLNode = leftAt(lev).get //TODO get
      val prev = startNode.rightUntil(_.right.get.el > e).get //TODO get
      val newNode = SLNode(e, prev.right.map(_.nodeKey), down.map(_.nodeKey), lev, lev != eLevel)
      insertNode(newNode)
      updateNode(prev, Some(newNode))
      if (lev < eLevel) insertOne(lev + 1, Some(newNode))
    }
    insertOne(0, None)
    true
  }

  private def newTopLevel(): Unit = {
    val prevNode = topNode
    val newLev = topNode.level + 1
    val topRight = topNode.rightUntil(_.right.isEmpty).get
    val newRight = SLNode(MaxSLElement, None, Some(topRight.nodeKey), newLev, true)
    topNode = SLNode(MinSLElement, Some(newRight.nodeKey), Some(prevNode.nodeKey), newLev, true)
  }

  def delete(e: SLElement): Boolean = if (contains(e)) {
    tower() foreach { leftNode =>
      leftNode.rightUntil(n => n.right.exists(nr => nr.el == e)).foreach { n =>
        updateNode(n, n.right.flatMap(_.right))
        n.right.foreach(deleteNode)
      }
    }
    true
  } else {
    false
  }

  //select level where element e will be putted
  private def selectLevel(e: SLElement) = {
    val r = Random
    r.setSeed((BigInt(e.key) % Long.MaxValue).toLong) //TODO check
    @tailrec
    def loop(lev: Int = 0): Int = {
      if (lev == topNode.level || r.nextDouble() > 0.5) lev
      else loop(lev + 1)
    }
    loop()
  }

  private def deleteNode(node: SLNode): Unit = {
    //TODO delete from DB
  }

  private def insertNode(node: SLNode): Unit = {
    //TODO insert to DB
  }

  private def updateNode(node: SLNode, newRightNode: Option[SLNode]): Unit = {
    node.right = newRightNode
  }

  /**
   * All nodes in a tower
   */
  @tailrec
  private def tower(n: SLNode = topNode, acc: Seq[SLNode] = Seq(topNode)): Seq[SLNode] = n.down match {
    case Some(downNode) => tower(downNode, downNode +: acc)
    case None => acc
  }

  override def toString: String = {
    def lev(n: SLNode, acc: Seq[SLNode] = Seq()): Seq[SLNode] = n.right match {
      case Some(rn) => lev(rn, n +: acc)
      case None => n +: acc
    }
    val levs = tower() map { leftNode =>
      leftNode.level + ": " + lev(leftNode).reverse.map(n => Base64.encode(n.el.key)).mkString(", ")
    }
    levs.mkString("\n")
  }
}

object SkipList {
  type SLKey = Array[Byte]
  type SLValue = Array[Byte]

  type NodeKey = Array[Byte]
  type NodeValue = Array[Byte]

}