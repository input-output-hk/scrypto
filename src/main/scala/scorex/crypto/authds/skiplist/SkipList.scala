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

  def elementProof(e: SLElement): SLProof = {
    val leftNode = findLeft(topNode, e)
    val leftProof = SLExistenceProof(leftNode.el, SLPath(hashTrack(leftNode.el)))
    if (leftNode.el.key sameElements e.key) {
      require(leftNode.el == e, "Can't generate proof for element with existing key but different value")
      leftProof
    } else {
      val rightNode = leftNode.right.get
      rightNode.recomputeHash
      val rightProof = if (rightNode.el < MaxSLElement) {
        Some(elementProof(rightNode.el).asInstanceOf[SLExistenceProof])
      } else {
        None
      }

      if (!SLNonExistenceProof(e, leftProof, rightProof).check(rootHash)) {
        rightProof match {
          case Some(rp) =>
            val left = leftProof
            val tower = left.proof.hashes.last sameElements hf(rp.e.bytes)
            val nonTower = left.proof.hashes.last sameElements hf.hash(hf(rp.e.bytes), rp.proof.hashes.last)
            val lpv = leftProof.check(rootHash)
            val rpv = rp.check(rootHash)
            if (!(tower || nonTower)) {
              val rrnHash = Base58.encode(rightNode.right.get.hash)
              val rnHash = Base58.encode(rightNode.hash)
              val rnHashCalc = Base58.encode(hf.hash(hf.hash(rightNode.el.bytes), rightNode.right.get.hash))
              val renHashCalc = Base58.encode(rightNode.recomputeHash)
            }
            if (!lpv) {
              val p2 = elementProof(leftNode.el)
              val t = p2.check(rootHash)
              val fuck = ""

            }
          case _ =>
        }
      }



      SLNonExistenceProof(e, leftProof, rightProof)
    }
  }

  //  }.ensuring(_.check(rootHash))

  // find bottom node with current element
  def find(e: SLElement): Option[SLNode] = {
    val leftNode = findLeft(topNode, e)
    if (leftNode.el == e) Some(leftNode) else None
  }

  /**
   * find first BOTTOM node which element is bigger then current element
   */
  private def findLeft(node: SLNode, e: SLElement): SLNode = {
    findLeftTop(node, e).downUntil(_.down.isEmpty).get
  }

  /**
   * find first TOP node which element is bigger then current element
   */
  @tailrec
  private def findLeftTop(node: SLNode, e: SLElement): SLNode = {
    val prevNodeOpt = node.rightUntil(n => n.right.exists(rn => rn.el > e))
    require(prevNodeOpt.isDefined, s"Non-infinite element should have right node, $node")
    val prevNode = prevNodeOpt.get
    if (prevNode.el == e) {
      prevNode
    } else {
      prevNode.down match {
        case Some(dn: SLNode) => findLeftTop(dn, e)
        case _ => prevNode
      }
    }
  }


  def insert(e: SLElement, singleInsert: Boolean = true): Boolean = if (contains(e)) {
    false
  } else {
    val eLevel = selectLevel(e)
    if (eLevel == topNode.level) newTopLevel()
    def insertOne(levNode: SLNode): SLNode = {
      val prev = levNode.rightUntil(_.right.get.el > e).get
      lazy val downNode: Option[SLNode] = prev.down.map(dn => insertOne(dn))
      val newNode = SLNode(e, prev.right.map(_.nodeKey), downNode.map(_.nodeKey), levNode.level, levNode.level != eLevel)
      saveNode(newNode, singleInsert)
      val prevUpdated = prev.copy(rightKey = Some(newNode.nodeKey))
      SLNode.unset(prev.nodeKey)
      saveNode(prevUpdated, singleInsert)
      newNode
    }
    insertOne(leftAt(eLevel).get)
    recomputeHashesForAffected(e, singleInsert)
    true
  }

  def update(updates: SkipListUpdate): Unit = {
    updates.toDelete foreach (n => delete(n, singleUpdate = false))
    deleteEmptyTopLevels()

    updates.toInsert.sorted.reverse foreach { e => insert(e, singleInsert = false) }

    topNode.recomputeHash
    SLNode.set(TopNodeKey, topNode)
    SLNode.cleanCache()
    storage.commit()
  }

  def delete(e: SLElement, singleUpdate: Boolean = true): Unit = {
    def deleteOne(node: SLNode): Unit = {
      val prev = node.rightUntil(_.right.get.el >= e).get
      val right = prev.right
      if (right.exists(_.el == e)) {
        val newNode = prev.copy(rightKey = prev.right.flatMap(_.rightKey))
        SLNode.unset(prev.nodeKey)
        saveNode(newNode, commit = singleUpdate)
        prev.right.foreach(nr => SLNode.unset(nr.nodeKey))
      }
      prev.down.foreach(deleteOne)
    }
    deleteOne(topNode)
    if (singleUpdate) deleteEmptyTopLevels()
    recomputeHashesForAffected(e, singleUpdate)
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
          oldTop.rightKey.foreach(key => SLNode.unset(key))
          SLNode.unset(oldTop.nodeKey)
          topNode.recomputeHash
          SLNode.set(TopNodeKey, topNode)
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


  private def affectedNodes(trackElement: SLElement, node: SLNode = topNode): Seq[SLNode] = {
    val prevElement = topNode.downUntil(_.down.isEmpty).get.rightUntil(n => n.right.get.el >= trackElement).map(_.el).get
    require(prevElement < trackElement)
    @tailrec
    def trackLeft(node: SLNode, e: SLElement, acc: Seq[SLNode]): Seq[SLNode] = {
      val affected = node.rightUntilTrack(n => n.el >= e)
      val prevNodeOpt = node.rightUntil(n => n.right.exists(rn => rn.el > e))
      require(prevNodeOpt.isDefined, s"Non-infinite element should have right node, $node")
      val prevNode = prevNodeOpt.get
      prevNode.down match {
        case Some(dn: SLNode) => trackLeft(dn, e, (node +: affected) ++ acc)
        case _ => (node +: affected) ++ acc
      }
    }
    trackLeft(topNode, prevElement, Seq())
  }


  private def recomputeHashesForAffected(e: SLElement, commit: Boolean = true): Unit = {
    val a = affectedNodes(e).map(n => Base58.encode(n.el.bytes).take(12) + "|" + n.level)
    affectedNodes(e).foreach { n =>
      n.recomputeHash
      SLNode.set(n.nodeKey, n)
    }
    topNode.recomputeHash
    SLNode.set(TopNodeKey, topNode)
    storage.commit()
  }

  private def saveNode(node: SLNode, isTop: Boolean = false, commit: Boolean = true): Unit = {
    node.recomputeHash
    SLNode.set(node.nodeKey, node)
    if (isTop) SLNode.set(TopNodeKey, node)
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
    val elements = topNode.downUntil(_.down.isEmpty).get.rightUntilTrack(n => n.right.isEmpty).map(_.el).sorted
    val Size = 12
    val levs = tower() map { leftNode =>
      leftNode.level + ": " + elements.map { e =>
        leftNode.rightUntil(n => n.el == e).map(el => Base58.encode(e.bytes).take(Size)).getOrElse("            ")
      }.mkString(", ")
    }
    levs.reverse.mkString("\n")
  }
}

object SkipList {
  type SLKey = Array[Byte]
  type SLValue = Array[Byte]
}