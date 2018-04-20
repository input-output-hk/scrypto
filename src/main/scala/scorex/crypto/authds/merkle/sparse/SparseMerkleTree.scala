package scorex.crypto.authds.merkle.sparse

import com.google.common.primitives.Longs
import scorex.crypto.authds.LeafData
import scorex.crypto.hash._

import scala.collection.mutable
import scala.util.Random

/**
  *
  * An implementation of sparse Merkle tree of predefined height. Supported operations are append new leaf and update
  * previously appended leaf.
  *
  * @param topNode
  * @param height - W parameter from the paper, defines how many bits in the key, up to 127
  * @tparam D
  */
class SparseMerkleTree[D <: Digest](val topNode: Option[Node[D]],
                                    val height: Byte,
                                    val lastProof: SparseMerkleProof[D])(implicit hf: CryptographicHash[D]) {
  lazy val lastIndex: Node.ID = lastProof.idx

  lazy val rootDigest: Option[D] = topNode.map(_.hash)

  private def firstDivergingBitPosition(idx1: BigInt, idx2: BigInt, max: Byte): Option[Byte] = {
    ((max - 1) to(0, -1)).foreach { bi =>
      if (idx1.testBit(bi) != idx2.testBit(bi)) return Some(bi.toByte)
    }
    None
  }

  private def updateProof(changesIdx: Node.ID,
                          changeLeafData: Option[LeafData],
                          changesPath: Vector[Option[D]],
                          proof: SparseMerkleProof[D]) = {
    firstDivergingBitPosition(proof.idx, changesIdx, height) match {
      case None => proof.copy(leafDataOpt = changeLeafData)
      case Some(divergingIndex) =>
        proof.copy(levels = proof.levels.updated(divergingIndex, changesPath(divergingIndex)))
    }
  }

  private def increaseCapacity() = {
    val li = lastIndex + 1

    val path = lastProof.propagateChanges(None)._2
    val siblings = lastProof.levels

    val lastIndexBits = SparseMerkleTree.indexToBits(lastIndex, height)
    val newLastIndexBits = SparseMerkleTree.indexToBits(lastIndex + 1, height)
    val vec = mutable.ArrayBuffer.fill[Option[D]](height)(None)

    (height - 1).to(0, -1).foldLeft(false) { case (oldDiverged, bitIdx) =>
      val oldBit = lastIndexBits(bitIdx)
      val newBit = newLastIndexBits(bitIdx)

      val diverged = oldDiverged || (oldBit != newBit)

      val updElem = if (!diverged) siblings(bitIdx) else if (!newBit) None else path(bitIdx)

      vec.update(bitIdx, updElem)

      diverged
    }

    val newLevels = vec.toVector

    val newLastProof = lastProof.copy(idx = li, levels = newLevels)

    assert(newLastProof.valid(rootDigest, height))

    newLastProof
  }

  /**
    * Both append and update ops are here.
    *
    * @param proof       - proof for some leaf
    * @param newLeafData - new data for the leaf
    * @param filterFn
    */
  def update(proof: SparseMerkleProof[D],
             newLeafData: Option[LeafData],
             proofsToUpdate: Seq[SparseMerkleProof[D]] = Seq(),
             filterFn: SparseMerkleTree.FilterFn = SparseMerkleTree.passAllFilterFn): (SparseMerkleTree[D], Seq[SparseMerkleProof[D]]) = {

    val proofIdx = proof.idx

    require(proof.levels.size == height)
    require(lastProof.levels.size == height)
    require(proofIdx <= lastIndex + 1)
    require(filterFn(proofIdx, newLeafData))
    require(proof.valid(rootDigest, height))


    val (newRoot, changes) = proof.propagateChanges(newLeafData)

    val lp = if (proofIdx == lastIndex) increaseCapacity() else lastProof

    val newLp = updateProof(proofIdx, newLeafData, changes, lp)

    val updatedProofs = proofsToUpdate.map(p => updateProof(proofIdx, newLeafData, changes, p))

    val updTree = new SparseMerkleTree[D](newRoot, height, newLp)

    assert(updTree.lastProof.valid(updTree.rootDigest, updTree.height))

    updTree -> updatedProofs
  }
}

object SparseMerkleTree {

  type FilterFn = (Node.ID, Option[LeafData]) => Boolean

  val passAllFilterFn: FilterFn = (_: Node.ID, _: Option[LeafData]) => true

  def zeroProof[D <: Digest](height: Byte) = SparseMerkleProof[D](0, None, (1 to height).map(_ => None).toVector)

  def emptyTree[D <: Digest](height: Byte)(implicit hf: CryptographicHash[D]): SparseMerkleTree[D] =
    new SparseMerkleTree[D](None, height, zeroProof[D](height))

  //0 == false == left, 1 == true == right

  def indexToBits(idx: Node.ID, height: Byte) = (0 to height - 1).map(i => idx.testBit(i))

  def indexToBitsReverse(idx: Node.ID, height: Byte) = (height - 1).to(0, -1).map(i => idx.testBit(i))
}

/**
  *
  * @param idx
  * @param leafDataOpt - leaf bytes, or null
  * @param levels      - bottom-up levels
  * @tparam D
  */
case class SparseMerkleProof[D <: Digest](idx: Node.ID,
                                          leafDataOpt: Option[LeafData],
                                          levels: Vector[Option[D]]) {

  def propagateChanges(leafDataOpt: Option[LeafData])
                      (implicit hf: CryptographicHash[D]): (Option[Node[D]], Vector[Option[D]]) = {
    val height = levels.size.toByte

    val leafOpt: Option[Node[D]] = leafDataOpt.map(leafData => Leaf(idx, leafData))
    val leafOptHash = leafOpt.map(_.hash)

    val sides = SparseMerkleTree.indexToBits(idx, height)

    val (rootHashOpt, wayDigests) = levels.zip(sides).foldLeft(leafOpt -> Vector[Option[D]](leafOptHash)) { case ((nodeOpt, collected), (ndigOpt, side)) =>
      val neighbourOpt: Option[LeafHash[D]] = ndigOpt.map(ndig => LeafHash[D](ndig))
      val updLevel = ((nodeOpt, neighbourOpt) match {
        case (None, None) => None
        case _ =>
          Some {
            if (side) InternalNode(neighbourOpt, nodeOpt) else InternalNode(nodeOpt, neighbourOpt)
          }
      }): Option[Node[D]]
      updLevel -> (collected :+ updLevel.map(_.hash))
    }
    rootHashOpt -> wayDigests.dropRight(1)
  }

  def valid(expectedRootHash: Option[D], height: Byte)(implicit hf: CryptographicHash[D]): Boolean = {
    require(levels.size == height)

    val calcRootOpt = propagateChanges(leafDataOpt: Option[LeafData])._1

    (calcRootOpt, expectedRootHash) match {
      case (Some(calcRoot), Some(expRoot)) => calcRoot.hash sameElements expRoot
      case (None, None) => true
      case _ => false
    }
  }
}


object TreeTester extends App {

  implicit val hf: CryptographicHash[Digest32] = new Blake2b256Unsafe

  (1 to 2000000).foreach(i => hf.hash(i.toString))

  val height: Byte = 30

  val tree0 = SparseMerkleTree.emptyTree(height)

  assert(tree0.lastProof.valid(tree0.rootDigest, height)(hf))

  val zp = SparseMerkleTree.zeroProof[Digest32](height)

  val zp1 = zp.copy(idx = 1)

  val (tree1, updProofs) = tree0.update(zp, Some(LeafData @@ Longs.toByteArray(5)), Seq(zp))


  assert(zp.valid(tree0.rootDigest, height)(hf))
  assert(zp1.valid(tree0.rootDigest, height)(hf))
  assert(updProofs.head.valid(tree1.rootDigest, height)(hf))

  assert(tree1.lastProof.valid(tree1.rootDigest, height)(hf))

  val tree2 = tree1.update(tree1.lastProof, Some(LeafData @@ Longs.toByteArray(10)))._1

  assert(tree2.lastProof.valid(tree2.rootDigest, height)(hf))

  println(tree2.topNode)

  val t0 = System.currentTimeMillis()
  (1 to 10000).foldLeft(SparseMerkleTree.emptyTree(height) -> Seq[SparseMerkleProof[Digest32]]()) { case ((tree, proofs), _) =>

    val (newProofs, proof, newValue) = if (Random.nextInt(3) == 0 && proofs.nonEmpty) {
      val nps = Random.shuffle(proofs)
      (nps.tail, nps.head, None)
    } else {
      val nps = if (Random.nextInt(2) == 0 && proofs.size < 5) proofs :+ tree.lastProof else proofs
      (nps, tree.lastProof, Some(LeafData @@ Longs.toByteArray(Random.nextInt())))
    }

    tree.update(proof, newValue, newProofs)
  }
  val t = System.currentTimeMillis()
  println((t - t0) + " ms.")
}


object BlockchainSimulator {

  type PubKey = Array[Byte]

  case class Transaction(amount: Long,
                         sender: PubKey,
                         recipient: PubKey,
                         senderBalance: Long,
                         senderBalanceProof: Long)

  case class Block(transactions: Seq[Transaction])

  val txsCache = new mutable.ArrayBuffer()

  val txsPerBlock = 500
  val numOfBlocks = 1000000

  val height = 30



}
