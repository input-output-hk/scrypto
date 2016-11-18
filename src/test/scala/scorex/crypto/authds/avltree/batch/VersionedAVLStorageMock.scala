package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.avltree.ProverNodes

import scala.collection.mutable

class VersionedAVLStorageMock extends VersionedAVLStorage {
  private val InitialVersion = Array.fill(32)(11: Byte)

  private var v: Version = InitialVersion

  override def isEmpty: Boolean = v sameElements InitialVersion

  // Map from version to topNode
  private val savedNodes: mutable.Map[mutable.WrappedArray[Byte], ProverNodes] = mutable.Map()

  override def update(topNode: ProverNodes): Unit = {
    v = topNode.label
    savedNodes(topNode.label) = topNode
  }

  override def rollback(version: Version): ProverNodes = savedNodes(version)

  override def version: Version = v
}
