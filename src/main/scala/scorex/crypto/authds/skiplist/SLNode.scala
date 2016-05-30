package scorex.crypto.authds.skiplist

import scala.annotation.tailrec

case class SLNode(el: SLElement, var right: Option[SLNode], down: Option[SLNode], level: Int, isTower: Boolean) {

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
