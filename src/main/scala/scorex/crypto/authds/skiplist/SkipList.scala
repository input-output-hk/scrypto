package scorex.crypto.authds.skiplist

import scala.annotation.tailrec
import scala.util.Random

class SkipList {

  //top left node
  private var topNode: SLNode = SLNode(MinSLElement, Some(SLNode(MaxSLElement, None, None, 0)), None, 0)

  private def leftAt(l: Int): Option[SLNode] = {
    require(l <= topNode.level)
    topNode.downUntil(_.level == l)
  }

  def contains(e: SLElement): Boolean = find(e).isDefined

  // find top node with current element
  private def find(e: SLElement): Option[SLNode] = {
    @tailrec
    def loop(node: SLNode): Option[SLNode] = {
      val prevNodeOpt = node.rightUntil(n => n.right.exists(rn => rn.el > e))
      require(prevNodeOpt.isDefined, "Non-infinite element should have right node")
      val prevNode = prevNodeOpt.get
      if (prevNode.el == e) prevNodeOpt
      else prevNode.down match {
        case Some(dn) => loop(dn)
        case _ => None
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
      val newNode = SLNode(e, prev.right, down, lev)
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
    val newRight = SLNode(MaxSLElement, None, Some(topRight), newLev)
    topNode = SLNode(MinSLElement, Some(newRight), Some(prevNode), newLev)
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
    r.setSeed(e.intKey.toLong) //TODO check
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
      leftNode.level + ": " + lev(leftNode).reverse.map(_.el.intKey % Int.MaxValue).mkString(", ")
    }
    levs.mkString("\n")
  }
}
