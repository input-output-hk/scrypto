package scorex.crypto.authds.avltree.batch

import scala.collection.mutable
import scala.util.Try

class VersionedAVLStorageMock extends VersionedAVLStorage {
  private val InitialVersion = Array.fill(32)(11: Byte)

  private var v: Version = InitialVersion

  // Map from version to topNode
  private val savedNodes: mutable.Map[mutable.WrappedArray[Byte], (ProverNodes, Int)] = mutable.Map()

  override def update(prover: BatchAVLProver[_]): Try[Unit] = Try {
    v = prover.digest
    savedNodes(v) = (prover.topNode, prover.rootNodeHeight)
  }

  override def rollback(version: Version): Try[(ProverNodes, Int)] = {
    Try(savedNodes(version))
  }

  override def version: Option[Version] = if(v.sameElements(InitialVersion)) None else Some(v)

  override def rollbackVersions: Iterable[Version] = Seq(v)
}
