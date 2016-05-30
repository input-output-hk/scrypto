package scorex.crypto.authds.skiplist

import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.annotation.tailrec

case class SLNode(el: SLElement, var right: Option[SLNode], down: Option[SLNode], level: Int, isTower: Boolean) {


  //  private def path()(implicit hf: CommutativeHash[_]): Seq[CryptographicHash#Digest] = right match {
  //    case Some(rn) =>
  //      down match {
  //        case Some(dn) =>
  //          if (rn.isTower) dn.hash +: rn.path()
  //          else rn.hash +: dn.path()
  //        case None =>
  //          if (rn.isTower) Seq( rn.el.bytes)
  //          else Seq( rn.hash)
  //      }
  //    case None => Array.empty
  //  }
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
            if (rn.isTower) Seq(rn.el.bytes)
            else Seq(rn.hash)
          } else {
            el.bytes +: rn.hashTrack(trackElement)
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
          if (rn.isTower) hf.hash(el.bytes, rn.el.bytes)
          else hf.hash(el.bytes, rn.hash)
      }
    case None => emptyHash
  }


  def rightUntil(p: SLNode => Boolean): Option[(SLNode, Seq[SLNode])] = {
    @tailrec
    def loop(node: SLNode = this, visited: Seq[SLNode] = Seq()): Option[(SLNode, Seq[SLNode])] = if (p(node)) {
      Some((node, node +: visited))
    } else {
      node.right match {
        case Some(rn) => loop(rn, visited)
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
