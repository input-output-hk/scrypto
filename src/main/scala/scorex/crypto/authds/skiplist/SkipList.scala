package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.authds.skiplist.SLNode.{SLNodeKey, SLNodeValue}
import scorex.crypto.authds.storage.{KVStorage, StorageType}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.annotation.tailrec

class SkipList[HF <: CommutativeHash[_], ST <: StorageType](implicit storage: KVStorage[SLNodeKey, SLNodeValue, ST],
                                                            hf: HF) {

  private val TopNodeKey: SLNodeKey = Array(-128: Byte)

  //top left node
  var topNode: SLNode = storage.get(TopNodeKey) match {
    case Some(tn) => SLNode.parseBytes(tn).get
    case None =>
      val topRight: SLNode = SLNode(MaxSLElement, None, None, 0, isTower = true)
      val topNode: SLNode = SLNode(MinSLElement, Some(topRight.nodeKey), None, 0, isTower = true)
      saveNode(topRight)
      saveNode(topNode, isTop = true)
      topNode
  }

  private def leftAt(l: Int): Option[SLNode] = {
    require(l <= topNode.level)
    topNode.downUntil(_.level == l)
  }

  def rootHash: CryptographicHash#Digest = topNode.hash

  def contains(e: SLElement): Boolean = find(e).isDefined

  def elementProof(e: SLElement): Option[SLAuthData] = find(e).map { n =>
    SLAuthData(e.bytes, SLPath(hashTrack(e)))
  }

  // find bottom node with current element
  def find(e: SLElement): Option[SLNode] = {
    @tailrec
    def loop(node: SLNode): Option[SLNode] = {
      val prevNodeOpt = node.rightUntil(n => n.right.exists(rn => rn.el > e))
      require(prevNodeOpt.isDefined, "Non-infinite element should have right node")
      val prevNode = prevNodeOpt.get
      prevNode.down match {
        case Some(dn: SLNode) => loop(dn)
        case _ => if (prevNode.el == e) Some(node) else None
      }
    }
    loop(topNode)
  }

  def insert(e: SLElement, singleInsert: Boolean = true): Boolean = if (contains(e)) {
    false
  } else {
    val eLevel = selectLevel(e)
    if (eLevel == topNode.level) newTopLevel()
    def insertOne(lev: Int, down: Option[SLNode]): Unit = if (lev <= eLevel) {
      val startNode = leftAt(lev).get //TODO get
      val prev = startNode.rightUntil(_.right.get.el > e).get //TODO get
      val newNode = SLNode(e, prev.right.map(_.nodeKey), down.map(_.nodeKey), lev, lev != eLevel)
      saveNode(newNode, singleInsert)
      val prevUpdated = prev.copy(rightKey = Some(newNode.nodeKey))
      storage.unset(prev.nodeKey)
      saveNode(prevUpdated, singleInsert)
      if (lev < eLevel) insertOne(lev + 1, Some(newNode))
    }
    insertOne(0, None)
    recomputeHashesForAffected(e, singleInsert)
    true
  }

  def update(updates: SkipListUpdate): Unit = {
    updates.toDelete foreach (n => delete(n, singleUpdate = false))
    deleteEmptyTopLevels()

    updates.toInsert foreach { e => insert(e, singleInsert = false) }

    topNode.recomputeHash
    storage.set(TopNodeKey, topNode.bytes)
    storage.commit()
  }

  def delete(e: SLElement, singleUpdate: Boolean = true): Boolean = if (contains(e)) {
    tower() foreach { leftNode =>
      leftNode.rightUntil(n => n.right.exists(nr => nr.el == e)).foreach { n =>
        val newNode = n.copy(rightKey = n.right.flatMap(_.rightKey))
        storage.unset(n.nodeKey)
        saveNode(newNode, commit = singleUpdate)
        n.right.foreach(nr => storage.unset(nr.nodeKey))
      }
    }
    if (singleUpdate) deleteEmptyTopLevels()
    recomputeHashesForAffected(e, singleUpdate)
    true
  } else {
    false
  }

  private def newTopLevel(): Unit = {
    val prevNode = topNode
    val newLev = topNode.level + 1
    val topRight = topNode.rightUntil(_.right.isEmpty).get
    val newRight = SLNode(MaxSLElement, None, Some(topRight.nodeKey), newLev, isTower = true)
    topNode = SLNode(MinSLElement, Some(newRight.nodeKey), Some(prevNode.nodeKey), newLev, isTower = true)
    saveNode(newRight)
    saveNode(topNode, isTop = true)
  }

  private def deleteEmptyTopLevels(): Unit = {
    topNode.down match {
      case Some(dn) =>
        if (dn.right.map(n => n.el == MaxSLElement).getOrElse(true)) {
          val oldTop = topNode
          topNode = dn
          oldTop.rightKey.foreach(key => storage.unset(key))
          storage.unset(oldTop.nodeKey)
          topNode.recomputeHash
          storage.set(TopNodeKey, topNode.bytes)
          storage.commit()
          deleteEmptyTopLevels()
        }
      case None =>
    }
  }

  private def hashTrack(trackElement: SLElement, n: SLNode = topNode): Seq[CryptographicHash#Digest] = n.right match {
    case Some(rn) =>
      n.down match {
        case Some(dn) =>
          if (rn.isTower) hashTrack(trackElement, dn)
          else if (rn.el > trackElement) rn.hash +: hashTrack(trackElement, dn)
          else dn.hash +: hashTrack(trackElement, rn)
        case None =>
          if (rn.el > trackElement) {
            if (rn.isTower) Seq(hf.hash(rn.el.bytes))
            else Seq(rn.hash)
          } else {
            hf.hash(n.el.bytes) +: hashTrack(trackElement, rn)
          }
      }
    case None => Seq(SLNode.emptyHash)
  }


  private def affectedNodes(trackElement: SLElement, node: SLNode = topNode): Seq[SLNode] = node.right match {
    case Some(rn) =>
      node.down match {
        case Some(dn) =>
          if (rn.isTower) node +: affectedNodes(trackElement, dn)
          else if (rn.el > trackElement) node +: affectedNodes(trackElement, dn)
          else node +: affectedNodes(trackElement, rn)
        case None =>
          if (rn.el > trackElement) {
            Seq(node)
          } else {
            node +: affectedNodes(trackElement, rn)
          }
      }
    case None => Seq.empty
  }


  private def recomputeHashesForAffected(e: SLElement, commit: Boolean = true): Unit = {
    affectedNodes(e).reverse.foreach { n =>
      n.recomputeHash
      storage.set(n.nodeKey, n.bytes)
    }
    topNode.recomputeHash
    storage.set(TopNodeKey, topNode.bytes)
    storage.commit()
  }

  private def saveNode(node: SLNode, isTop: Boolean = false, commit: Boolean = true): Unit = {
    node.recomputeHash
    storage.set(node.nodeKey, node.bytes)
    if (isTop) storage.set(TopNodeKey, node.bytes)
    if (commit) storage.commit()
  }


  //select level where element e will be putted
  private def selectLevel(e: SLElement) = {
    @tailrec
    def loop(lev: Int = 0): Int = {
      if (lev == topNode.level) lev
      else if (hf.hash(e.key ++ Ints.toByteArray(lev)).head.toInt < 0) lev
      else loop(lev + 1)
    }
    loop()
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
      leftNode.level + ": " + lev(leftNode).reverse.map(n => Base58.encode(n.hash).take(8)).mkString(", ")
    }
    levs.reverse.mkString("\n")
  }
}

object SkipList {
  type SLKey = Array[Byte]
  type SLValue = Array[Byte]
}