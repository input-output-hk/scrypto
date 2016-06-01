package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.authds.skiplist.SLNode.SLNodeKey
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}
import scorex.utils.Booleans

import scala.annotation.tailrec

case class SLNode(el: SLElement, rightKey: Option[SLNodeKey], downKey: Option[SLNodeKey], level: Int, isTower: Boolean) {


  lazy val down: Option[SLNode] = ???
  var right: Option[SLNode] = None

  val nodeKey: Array[Byte] = el.key ++ Ints.toByteArray(level)
  val bytes: Array[Byte] = el.bytes ++ Ints.toByteArray(level) ++ Booleans.toByteArray(isTower) ++
    Ints.toByteArray(rightKey.map(_.length).getOrElse(0)) ++ rightKey.getOrElse(Array()) ++
    Ints.toByteArray(downKey.map(_.length).getOrElse(0)) ++ downKey.getOrElse(Array())

  private val emptyHash: Array[Byte] = Array(0: Byte)

  def hashTrack(trackElement: SLElement)(implicit hf: CommutativeHash[_]): Seq[CryptographicHash#Digest] = right match {
    case Some(rn) =>
      down match {
        case Some(dn) =>
          if (rn.isTower) dn.hashTrack(trackElement)
          else if (rn.el > trackElement) rn.hash +: dn.hashTrack(trackElement)
          else dn.hash +: rn.hashTrack(trackElement)
        case None =>
          if (rn.el > trackElement) {
            if (rn.isTower) Seq(hf.hash(rn.el.bytes))
            else Seq(rn.hash)
          } else {
            hf.hash(el.bytes) +: rn.hashTrack(trackElement)
          }

      }
    case None => Seq(emptyHash)
  }


  def hash(implicit hf: CommutativeHash[_]): CryptographicHash#Digest = right match {
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


  def rightUntil(p: SLNode => Boolean): Option[SLNode] = {
    @tailrec
    def loop(node: SLNode = this): Option[SLNode] = if (p(node)) {
      Some(node)
    } else {
      node.right match {
        case Some(rn) => loop(rn)
        case None => None
      }
    }
    loop()
  }

  def downUntil(p: SLNode => Boolean): Option[SLNode] = {
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

  def parseBytes(bytes: Array[Byte]): SLNode = {
    val keySize = Ints.fromByteArray(bytes.slice(0, 4))
    val valueSize = Ints.fromByteArray(bytes.slice(4, 8))
    val el = SLElement.parseBytes(bytes.slice(0, 8 + keySize + valueSize))
    val level = Ints.fromByteArray(bytes.slice(8 + keySize + valueSize, 12 + keySize + valueSize))
    val isTower = Booleans.fromByteArray(bytes.slice(12 + keySize + valueSize, 13 + keySize + valueSize))
    val rkSize = Ints.fromByteArray(bytes.slice(13 + keySize + valueSize, 17 + keySize + valueSize))
    val rKey = if (rkSize == 0) None else Some(bytes.slice(17 + keySize + valueSize, 17 + keySize + valueSize + rkSize))
    val dkStart = 17 + keySize + valueSize + rkSize
    val dkSize = Ints.fromByteArray(bytes.slice(dkStart, dkStart + 4))
    val dKey = if (dkSize == 0) None else Some(bytes.slice(dkStart + 4, dkStart + 4 + dkSize))
    SLNode(el, rKey, dKey, level, isTower)
  }
}