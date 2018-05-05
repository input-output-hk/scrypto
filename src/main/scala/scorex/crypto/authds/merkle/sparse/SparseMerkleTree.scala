package scorex.crypto.authds.merkle.sparse

import com.google.common.primitives.Longs
import scorex.crypto.authds.LeafData
import scorex.crypto.hash._

import scala.collection.mutable
import scala.util.{Random, Try}

/**
  *
  * An implementation of sparse Merkle tree of predefined height. Supported operations are append new leaf and update
  * previously appended leaf.
  *
  * @param rootDigest - root hash of the tree
  * @param height     - W parameter from the paper, defines how many bits in the key, up to 127
  * @tparam D
  */
class SparseMerkleTree[D <: Digest](val rootDigest: Option[D],
                                    val height: Byte,
                                    val lastProof: SparseMerkleProof[D])(implicit hf: CryptographicHash[D]) {
  lazy val lastIndex: Node.ID = lastProof.idx

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

  private def increaseCapacity(): SparseMerkleProof[D] = {
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
             filterFn: SparseMerkleTree.FilterFn = SparseMerkleTree.passAllFilterFn):
  Try[(SparseMerkleTree[D], Seq[SparseMerkleProof[D]])] = Try {

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
  * Sparse Merkle tree proof for leaf
  *
  * @param idx         - index of a leaf
  * @param leafDataOpt - leaf bytes, or null
  * @param levels      - bottom-up levels
  * @tparam D
  */
case class SparseMerkleProof[D <: Digest](idx: Node.ID,
                                          leafDataOpt: Option[LeafData],
                                          levels: Vector[Option[D]]) {

  def propagateChanges(leafDataOpt: Option[LeafData])
                      (implicit hf: CryptographicHash[D]): (Option[D], Vector[Option[D]]) = {
    val height = levels.size.toByte

    val leafOpt: Option[Node[D]] = leafDataOpt.map(leafData => Leaf(idx, leafData))
    val leafOptHash = leafOpt.map(_.hash)

    val sides = SparseMerkleTree.indexToBits(idx, height)

    val (rootHashOpt, wayDigests) = levels.zip(sides).foldLeft(leafOpt -> Vector[Option[D]](leafOptHash)) {
      case ((nodeOpt, collected), (ndigOpt, side)) =>
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
    rootHashOpt.map(_.hash) -> wayDigests.dropRight(1)
  }

  def valid(expectedRootHash: Option[D], height: Byte)(implicit hf: CryptographicHash[D]): Boolean = {
    require(levels.size == height)

    val calcRootHash = propagateChanges(leafDataOpt: Option[LeafData])._1

    (calcRootHash, expectedRootHash) match {
      case (Some(calcRoot), Some(expRoot)) => calcRoot sameElements expRoot
      case (None, None) => true
      case _ => false
    }
  }

  def valid(tree: SparseMerkleTree[D])(implicit hf: CryptographicHash[D]): Boolean = valid(tree.rootDigest, tree.height)
}


object TreeTester extends App {

  implicit val hf: CryptographicHash[Digest32] = new Blake2b256Unsafe

  (1 to 2000000).foreach(i => hf.hash(i.toString))

  val height: Byte = 30

  val tree0 = SparseMerkleTree.emptyTree(height)

  assert(tree0.lastProof.valid(tree0.rootDigest, height)(hf))

  val zp = SparseMerkleTree.zeroProof[Digest32](height)

  val zp1 = zp.copy(idx = 1)

  val (tree1, updProofs) = tree0.update(zp, Some(LeafData @@ Longs.toByteArray(5)), Seq(zp)).get


  assert(zp.valid(tree0.rootDigest, height)(hf))
  assert(zp1.valid(tree0.rootDigest, height)(hf))
  assert(updProofs.head.valid(tree1.rootDigest, height)(hf))

  assert(tree1.lastProof.valid(tree1.rootDigest, height)(hf))

  val tree2 = tree1.update(tree1.lastProof, Some(LeafData @@ Longs.toByteArray(10))).get._1

  assert(tree2.lastProof.valid(tree2.rootDigest, height)(hf))


  val t0 = System.currentTimeMillis()
  (1 to 10000).foldLeft(SparseMerkleTree.emptyTree(height) -> Seq[SparseMerkleProof[Digest32]]()) { case ((tree, proofs), _) =>

    val (newProofs, proof, newValue) = if (Random.nextInt(3) == 0 && proofs.nonEmpty) {
      val nps = Random.shuffle(proofs)
      (nps.tail, nps.head, None)
    } else {
      val nps = if (Random.nextInt(2) == 0 && proofs.size < 5) proofs :+ tree.lastProof else proofs
      (nps, tree.lastProof, Some(LeafData @@ Longs.toByteArray(Random.nextInt())))
    }

    tree.update(proof, newValue, newProofs).get
  }
  val t = System.currentTimeMillis()
  println((t - t0) + " ms.")
}

object OpsBenchmark extends App {
  implicit val hf: CryptographicHash[Digest32] = new Blake2b256Unsafe

  val height: Byte = 50

  var tree = SparseMerkleTree.emptyTree(height)

  //bootstrapping

  val bSize = 10000

  var proof: SparseMerkleProof[Digest32] = null

  val tb0 = System.currentTimeMillis()
  (0 until bSize).foreach {i =>
    if(i == bSize/2) proof = tree.lastProof

    val proofsToUpdate = if(i >= bSize/2) {
      Seq(proof)
    } else Seq.empty[SparseMerkleProof[Digest32]]

    if(i%1000 == 0) println(s"$i elements added")
    val (t, p) = tree.update(tree.lastProof, Some(LeafData @@ Longs.toByteArray(i)), proofsToUpdate).get

    tree = t
    if(i >= bSize/2) proof = p.head
  }
  val tb = System.currentTimeMillis()
  println(s"bootstrapping time: ${tb-tb0}")

  val tv0 = System.currentTimeMillis()
  (1 to 1000).foreach(i => proof.valid(tree))
  val tv = System.currentTimeMillis()
  println(s"1000 updates time: ${tv-tv0} ms")



    val te0 = System.currentTimeMillis()
    (1 to 1000).foreach(_ =>
      tree.update(tree.lastProof, Some(LeafData @@ Longs.toByteArray(2)), Seq())
    )
    val te = System.currentTimeMillis()

    val tp0 = System.currentTimeMillis()
    (1 to 1000).foreach(_ =>
      tree.update(tree.lastProof, Some(LeafData @@ Longs.toByteArray(2)), Seq(proof))
    )
    val tp = System.currentTimeMillis()

    val tu = (tp-tp0) - (te-te0)

    println("1000 proof updates: " + tu)
}

object BlockchainSimulator extends App {

  type PubKey = Array[Byte]

  val PubKeyLength = 32

  implicit val hf: CryptographicHash[Digest32] = new Blake2b256Unsafe

  case class Transaction(amount: Long,
                         sender: PubKey,
                         recipient: PubKey,
                         coinBalance: Long,
                         coinProof: SparseMerkleProof[Digest32])

  object Transaction {
    def coinBytes(pubKey: PubKey, balance: Long) = Some(LeafData @@ (pubKey ++ Longs.toByteArray(balance)))

    def process(tx: Transaction,
                state: SparseMerkleTree[Digest32]):
    Try[(SparseMerkleTree[Digest32], Seq[SparseMerkleProof[Digest32]])] = Try {

      require(tx.amount <= tx.coinBalance)
      require(tx.coinProof.leafDataOpt.get sameElements coinBytes(tx.sender, tx.coinBalance).get)
      require(tx.coinProof.valid(state.rootDigest, height))

      val (state1, _) = state.update(tx.coinProof, None).get

      val (state2, proofs2) = state1.update(state1.lastProof,
        coinBytes(tx.recipient, tx.amount),
        Seq(state1.lastProof)).get

      if (tx.amount == tx.coinBalance) state2 -> proofs2
      else state2.update(state2.lastProof,
        coinBytes(tx.sender, tx.coinBalance - tx.amount),
        proofs2 :+ state2.lastProof).get
    }
  }

  case class Block(transactions: Seq[Transaction])

  val txsCache = new mutable.ArrayBuffer()
  val maxTxsCacheSize = 5000

  val txsPerBlock = 1000
  val numOfBlocks = 1000000

  val height = 30: Byte

  val godAccount = Array.fill(32)(0: Byte)
  val godBalance = 100000000000L //100B

  val emptyState = SparseMerkleTree.emptyTree(height)
  val (initialState, godProofs) = emptyState.update(emptyState.lastProof,
    Transaction.coinBytes(godAccount, godBalance),
    Seq(emptyState.lastProof)).get

  var godProof = godProofs.head
  var currentGodBalance = godBalance
  val txAmount = 10

  (1 to numOfBlocks).foldLeft(initialState) { case (beforeBlocktree, blockNum) =>
    val (afterTree, processingTime) = (1 to txsPerBlock).foldLeft(beforeBlocktree -> 0L) { case ((tree, totalTime), txNum) =>
      val recipient = hf(scala.util.Random.nextString(20))

      val tx = Transaction(txAmount, godAccount, recipient, currentGodBalance, godProof)

      val t0 = System.currentTimeMillis()
      val (updState, proofs) = Transaction.process(tx, tree).get //we generate always valid transaction
      val t = System.currentTimeMillis()

      currentGodBalance = currentGodBalance - txAmount
      godProof = proofs.last

      updState -> (totalTime + (t - t0))
    }

    println(s"Block $blockNum, processing time: $processingTime ms")
    println(godProof)

    afterTree
  }
}