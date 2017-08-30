package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.ADDigest
import scorex.crypto.hash.Digest

import scala.collection.mutable
import scala.util.Try

class VersionedAVLStorageMock[T <: Digest] extends VersionedAVLStorage[T] {

  private val DigestLength = 33

  private val InitialVersion = ADDigest @@ Array.fill(DigestLength)(11: Byte)

  private var v: ADDigest = InitialVersion

  override def isEmpty: Boolean = v sameElements InitialVersion

  // Map from version to topNode
  private val savedNodes: mutable.Map[mutable.WrappedArray[Byte], (ProverNodes[T], Int)] = mutable.Map()

  override def update(prover: BatchAVLProver[T, _]): Try[Unit] = Try {
    val newDigest = prover.digest
    assert(v.length == newDigest.length, s"Incorrect digest length: ${v.length} != ${newDigest.length}")
    v = newDigest
    savedNodes(v) = (prover.topNode, prover.rootNodeHeight)
  }

  override def rollback(version: ADDigest): Try[(ProverNodes[T], Int)] = {
    Try(savedNodes(version))
  }

  override def version: ADDigest = v
}
