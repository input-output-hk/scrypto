package scorex.crypto.authds.avltree.batch

import scorex.crypto.authds.ADDigest
import scorex.crypto.hash.Digest

import scala.collection.mutable
import scala.util.Try

class VersionedAVLStorageMock[D <: Digest] extends VersionedAVLStorage[D] {

  private val DigestLength = 33

  private val InitialVersion = ADDigest @@ Array.fill(DigestLength)(11: Byte)

  private var v: ADDigest = InitialVersion

  // Map from version to topNode
  private val savedNodes: mutable.Map[mutable.WrappedArray[Byte], (ProverNodes[D], Int)] = mutable.Map()


  override def rollback(version: ADDigest): Try[(ProverNodes[D], Int)] = {
    Try(savedNodes(version))
  }

  override def version: Option[ADDigest] = if(v.sameElements(InitialVersion)) None else Some(v)

  override def rollbackVersions: Iterable[ADDigest] = Seq(v)

  /**
    * Synchronize storage with prover's state
    *
    * @param prover - prover to synchronize storage with
    * @return
    */
  //ignoring additionalData
  override def update[K <: Array[Byte], V <: Array[Byte]](prover: BatchAVLProver[D, _],
                                                          additionalData: Seq[(K, V)]): Try[Unit] = Try {
    val newDigest = prover.digest
    assert(v.length == newDigest.length, s"Incorrect digest length: ${v.length} != ${newDigest.length}")
    v = newDigest
    savedNodes(v) = (prover.topNode, prover.rootNodeHeight)
  }
}
