package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.authds.skiplist.SLNode.{SLNodeKey, SLNodeValue}
import scorex.crypto.authds.storage.{KVStorage, StorageType}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash, Sha256}

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

  def rootHash: CryptographicHash#Digest = topNode.hash

  def contains(e: SLElement): Boolean = find(e).isDefined

  def extendedElementProof(e: SLElement): ExtendedSLProof = {
    val leftNode = findLeft(topNode, e, includeEquals = false)
    val leftProof = SLExistenceProof(leftNode.el, SLPath(hashTrack(leftNode.el)))
    val rightNode = leftNode.right.get
    val rightProof =
      if (rightNode.el < MaxSLElement) Some(SLExistenceProof(rightNode.el, SLPath(hashTrack(rightNode.el))))
      else None

    val rightNodeEl = if (rightNode.el.key sameElements e.key) rightNode.el else e
    ExtendedSLProof(rightNodeEl, leftProof, rightProof)
  }.ensuring(_.check(rootHash))


  def elementProof(e: SLElement): SLProof = {
    val leftNode = findLeft(topNode, e)
    val leftProof = SLExistenceProof(leftNode.el, SLPath(hashTrack(leftNode.el)))
    if (leftNode.el.key sameElements e.key) {
      require(leftNode.el == e, "Can't generate proof for element with existing key but different value")
      leftProof
    } else {
      val rightNode = leftNode.right.get
      val rightProof =
        if (rightNode.el < MaxSLElement) Some(SLExistenceProof(rightNode.el, SLPath(hashTrack(rightNode.el))))
        else None

      SLNonExistenceProof(e, leftProof, rightProof)
    }
  }

  // find bottom node with current element
  def find(e: SLElement): Option[SLNode] = {
    val leftNode = findLeft(topNode, e)
    if (leftNode.el == e) Some(leftNode) else None
  }

  /**
   * find first BOTTOM node which element is bigger then current element
   */
  private def findLeft(node: SLNode, e: SLElement, includeEquals: Boolean = true): SLNode = {
    findLeftTop(node, e, includeEquals).downUntil(_.down.isEmpty).get
  }

  /**
   * find first TOP node which element is lower or equal to current element
   */
  @tailrec
  private def findLeftTop(node: SLNode, e: SLElement, includeEquals: Boolean = true, minLev: Int = 0): SLNode = {
    val prevNodeOpt = if (includeEquals) node.rightUntil(n => n.right.exists(rn => rn.el > e))
    else node.rightUntil(n => n.right.exists(rn => rn.el >= e))

    require(prevNodeOpt.isDefined, s"Non-infinite element should have right node, $node")
    val prevNode = prevNodeOpt.get
    if (prevNode.el == e) {
      prevNode
    } else {
      prevNode.down match {
        case Some(dn: SLNode) if dn.level >= minLev => findLeftTop(dn, e, includeEquals, minLev)
        case _ => prevNode
      }
    }
  }

  def update(updates: SkipListUpdate, withProofs: Boolean = false): SLProofSeq = {
    val height = topNode.level

    if (updates.toDelete.nonEmpty) {
      require(!withProofs, "Proofs are not supported for delete operations")
      updates.toDelete foreach (n => delete(n, singleUpdate = withProofs))
      deleteEmptyTopLevels()
    }

    val toUpdateProofs: Seq[ProofToRecalculate] = updates.toUpdate.sorted.reverse flatMap { e =>
      val proof = if (withProofs) {
        Some(ProofToRecalculate(e, extendedElementProof(e)))
      } else None
      updateOne(e, singleUpdate = withProofs)
      proof
    }

    val toInsertProofs: Seq[ProofToRecalculate] = updates.toInsert.sorted.reverse flatMap { e =>
      val proof = if (withProofs) Some(ProofToRecalculate(e, extendedElementProof(e))) else None
      insert(e, singleInsert = withProofs)
      proof
    }

    topNode.recomputeHash
    SLNode.set(TopNodeKey, topNode)
    storage.commit()
    SLProofSeq(height, toUpdateProofs ++ toInsertProofs)
  }

  //Delete element with such a key and insert newE with the same height
  def updateOne(newE: SLElement, singleUpdate: Boolean = true): Boolean = if (contains(newE)) {
    val n = findLeftTop(topNode, newE)
    val lev = n.level
    delete(newE)
    insert(newE, singleUpdate, Some(lev))
  } else false

  def insert(e: SLElement, singleInsert: Boolean = true, levOpt: Option[Int] = None): Boolean = if (contains(e)) {
    false
  } else {
    val eLevel = levOpt.getOrElse(SkipList.selectLevel(e, topNode.level))
    if (eLevel == topNode.level) newTopLevel()
    def insertOne(levNode: SLNode): SLNode = {
      val prev = levNode.rightUntil(_.right.get.el > e).get
      val downNode: Option[SLNode] = prev.down.map(dn => insertOne(dn))
      val newNode = SLNode(e, prev.right.map(_.nodeKey), downNode.map(_.nodeKey), levNode.level, levNode.level != eLevel)
      saveNode(newNode, singleInsert)
      val prevUpdated = prev.copy(rightKey = Some(newNode.nodeKey))
      SLNode.unset(prev.nodeKey)
      saveNode(prevUpdated, singleInsert)
      newNode
    }

    insertOne(findLeftTop(topNode, e, includeEquals = true, minLev = eLevel))

    recomputeHashesForAffected(e, singleInsert)

    true
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

  @tailrec
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

  private def hashTrack(trackElement: SLElement, n: SLNode = topNode): Seq[LevHash] = {
    def hashTrackLoop(n: SLNode = topNode): Seq[LevHash] = {
      n.right match {
        case Some(rn) =>
          n.down match {
            case Some(dn) =>
              if (rn.isTower) hashTrackLoop(dn)
              else if (rn.el > trackElement) LevHash(rn.hash, n.level, Right) +: hashTrackLoop(dn)
              else LevHash(dn.hash, n.level, Down) +: hashTrackLoop(rn)
            case None =>
              if (rn.el > trackElement) {
                if (rn.isTower) Seq(LevHash(hf.hash(rn.el.bytes), n.level, Right))
                else Seq(LevHash(rn.hash, n.level, Right))
              } else {
                LevHash(hf.hash(n.el.bytes), n.level, Down) +: hashTrackLoop(rn)
              }
          }
        case None => Seq(LevHash(SLNode.emptyHash, 0, Down))
      }
    }
    hashTrackLoop().reverse
  }


  private def affectedNodes(trackElement: SLElement, node: SLNode = topNode): Seq[SLNode] = {
    val prevElement = findLeft(topNode, trackElement, includeEquals = false).el
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

  /**
   * All nodes in a tower
   */
  @tailrec
  private def tower(n: SLNode = topNode, acc: Seq[SLNode] = Seq(topNode)): Seq[SLNode] = n.down match {
    case Some(downNode) => tower(downNode, downNode +: acc)
    case None => acc
  }

  override def toString: String = {
    @tailrec
    def lev(n: SLNode, acc: Seq[SLNode] = Seq()): Seq[SLNode] = n.right match {
      case Some(rn) => lev(rn, n +: acc)
      case None => n +: acc
    }
    val elements = topNode.downUntil(_.down.isEmpty).get.rightUntilTrack(n => n.right.isEmpty).map(_.el).sorted
    val Size = 12
    val levs = tower() map { leftNode =>
      leftNode.level + ": " + elements.map { e =>
        leftNode.rightUntil(n => n.el == e).map(n => Base58.encode(n.hash).substring(0, Size)).getOrElse("            ")
      }.mkString(", ")
    }
    val elementsS = "e: " + elements.map(e => Base58.encode(hf(e.bytes)).take(Size)).mkString(", ")
    (elementsS +: levs).reverse.mkString("\n")
  }
}

object SkipList {
  type SLKey = Array[Byte]
  type SLValue = Array[Byte]

  /**
   * Select a level where element e will be putted
   */
  def selectLevel(e: SLElement, maxLev: Int): Int = {
    @tailrec
    def loop(lev: Int = 0): Int = {
      if (lev == maxLev) lev
      else if (Sha256(e.key ++ Ints.toByteArray(lev)).head.toInt < 0) lev
      else loop(lev + 1)
    }
    loop()
  }

}