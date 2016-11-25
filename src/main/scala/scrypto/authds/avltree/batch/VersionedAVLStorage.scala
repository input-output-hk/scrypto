package scrypto.authds.avltree.batch

import scrypto.authds.avltree.ProverNodes

import scala.util.Try

trait VersionedAVLStorage {

  type Version = Array[Byte]

  def update(topNode: ProverNodes): Try[Unit]

  def rollback(version: Version): Try[ProverNodes]

  def version: Version

  def isEmpty: Boolean

  def nonEmpty: Boolean = !isEmpty

}

object VersionedAVLStorage {
  type Version = Array[Byte]
}