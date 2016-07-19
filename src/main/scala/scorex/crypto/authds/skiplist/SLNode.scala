package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.authds.skiplist.SLNode._
import scorex.crypto.authds.storage.{KVStorage, StorageType}
import scorex.crypto.encode.{Base64, Base58}
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}
import scorex.utils.Booleans

import scala.annotation.tailrec
import scala.collection.concurrent.TrieMap
import scala.util.Try

case class SLNode(el: SLElement, rightKey: Option[SLNodeKey], downKey: Option[SLNodeKey], level: Int, isTower: Boolean)
                 (implicit storage: KVStorage[SLNodeKey, SLNodeValue, _]) {


  def down: Option[SLNode] = SLNode(downKey)

  def right: Option[SLNode] = SLNode(rightKey)

  var hash: CryptographicHash#Digest = Array.empty

  def setHash(h: CryptographicHash#Digest): Unit = hash = h

  def recomputeHash[ST <: StorageType](implicit hf: CommutativeHash[_],
                                       storage: KVStorage[SLNodeKey, SLNodeValue, ST]): CryptographicHash#Digest = {
    hash = computeHash
    hash
  }

  val nodeKey: Array[Byte] = el.key ++ Ints.toByteArray(level)

  def bytes: Array[Byte] = el.bytes ++ Ints.toByteArray(level) ++ Booleans.toByteArray(isTower) ++
    Ints.toByteArray(rightKey.map(_.length).getOrElse(0)) ++ rightKey.getOrElse(Array()) ++
    Ints.toByteArray(downKey.map(_.length).getOrElse(0)) ++ downKey.getOrElse(Array()) ++
    Ints.toByteArray(hash.length) ++ hash


  private def computeHash[ST <: StorageType](implicit hf: CommutativeHash[_],
                                             storage: KVStorage[SLNodeKey, SLNodeValue, ST]): CryptographicHash#Digest
  = right match {
    case Some(rn) =>
      down match {
        case Some(dn) =>
          if (rn.isTower) dn.hash
          else hf.hash(dn.hash, rn.hash)
        case None =>
          if (rn.isTower) hf.hash(hf.hash(el.bytes), hf.hash(rn.el.bytes))
          else hf.hash(hf.hash(el.bytes), rn.hash)
      }
    case None => emptyHash
  }


  def rightUntil[ST <: StorageType](p: SLNode => Boolean)
                                   (implicit storage: KVStorage[SLNodeKey, SLNodeValue, ST]): Option[SLNode] = {
    @tailrec
    def loop(node: SLNode = this): Option[SLNode] = {
      if (p(node)) {
        Some(node)
      } else {
        node.right match {
          case Some(rn) => loop(rn)
          case None => None
        }
      }
    }
    loop()
  }

  def rightUntilTrack[ST <: StorageType](p: SLNode => Boolean)
                                        (implicit storage: KVStorage[SLNodeKey, SLNodeValue, ST]): Seq[SLNode] = {
    def loop(node: SLNode = this, acc: Seq[SLNode] = Seq()): Seq[SLNode] = if (p(node)) {
      node +: acc
    } else {
      node.right match {
        case Some(rn) => loop(rn, node +: acc)
        case None => acc
      }
    }
    loop()
  }


  def downUntil[ST <: StorageType](p: SLNode => Boolean)
                                  (implicit storage: KVStorage[SLNodeKey, SLNodeValue, ST]): Option[SLNode] = {
    @tailrec
    def loop(node: SLNode = this): Option[SLNode] = if (p(node)) {
      Some(node)
    } else {
      node.down match {
        case Some(rn) => loop(rn)
        case None => None
      }
    }
    loop()
  }

}

object SLNode {
  type SLNodeKey = Array[Byte]
  type SLNodeValue = Array[Byte]

  private val slnodeCache: TrieMap[String, Option[SLNode]] = TrieMap.empty
  private val CacheSize: Int = 10000

  def apply(keyOpt: Option[SLNodeKey])(implicit storage: KVStorage[SLNodeKey, SLNodeValue, _]): Option[SLNode] = {
    keyOpt.flatMap { key =>
      slnodeCache.getOrElseUpdate(Base64.encode(key), storage.get(key).flatMap(b => SLNode.parseBytes(b).toOption))
    }
  }

  def unset(key: SLNodeKey)(implicit storage: KVStorage[SLNodeKey, SLNodeValue, _]): Unit = {
    storage.unset(key)
    slnodeCache.remove(Base64.encode(key))
  }

  def set(key: SLNodeKey, node: SLNode)(implicit storage: KVStorage[SLNodeKey, SLNodeValue, _]): Unit = {
    slnodeCache.put(Base64.encode(key), Some(node))
    storage.set(key, node.bytes)
  }

  def cleanCache(): Unit = if (slnodeCache.size > CacheSize) slnodeCache.clear()

  def parseBytes(bytes: Array[Byte])(implicit storage: KVStorage[SLNodeKey, SLNodeValue, _]): Try[SLNode] = Try {
    val el = SLElement.parseBytes(bytes).get
    val startFrom = el.bytes.length
    val level = Ints.fromByteArray(bytes.slice(startFrom, startFrom + 4))
    val isTower = Booleans.fromByteArray(bytes.slice(startFrom + 4, startFrom + 5))
    val rkSize = Ints.fromByteArray(bytes.slice(startFrom + 5, startFrom + 9))
    val dkStart = startFrom + 9 + rkSize
    val rKey = if (rkSize == 0) None else Some(bytes.slice(startFrom + 9, dkStart))
    val dkSize = Ints.fromByteArray(bytes.slice(dkStart, dkStart + 4))
    val dKey = if (dkSize == 0) None else Some(bytes.slice(dkStart + 4, dkStart + 4 + dkSize))
    val hashSize = Ints.fromByteArray(bytes.slice(dkStart + 4 + dkSize, dkStart + 8 + dkSize))
    val hash = bytes.slice(dkStart + 8 + dkSize, dkStart + 8 + dkSize + hashSize)
    val node = SLNode(el, rKey, dKey, level, isTower)
    node.setHash(hash)
    node
  }

  val emptyHash: Array[Byte] = Array.fill(32)(0: Byte)

}