package scorex.crypto.authds.avltree.batch

import scala.collection.mutable
import scala.util.Try

class VersionedAVLStorageMock extends VersionedAVLStorage {
  private val InitialVersion = Array.fill(32)(11: Byte)

  private var v: Version = InitialVersion

  override def isEmpty: Boolean = v sameElements InitialVersion

  // Map from version to topNode
  private val savedNodes: mutable.Map[mutable.WrappedArray[Byte], (ProverNodes, Int)] = mutable.Map()

  override def update(prover: BatchAVLProver[_]): Try[Unit] = Try {
    v = prover.topNode.label
    savedNodes(prover.topNode.label) = (prover.topNode, prover.topNodeHeight)
  }

  override def rollback(version: Version): Try[(ProverNodes, Int)] = {
    Try(savedNodes(version))
  }

  override def version: Version = v
}
