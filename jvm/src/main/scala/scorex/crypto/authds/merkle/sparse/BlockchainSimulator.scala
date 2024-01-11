package scorex.crypto.authds.merkle.sparse

import scorex.crypto.authds.LeafData

import scala.util.Try
import scorex.crypto.hash.{CryptographicHash, Digest32, Blake2b256Unsafe}

import scala.collection.mutable
import scorex.utils.Longs

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
  val (initialState: SparseMerkleTree[Digest32], godProofs:  Seq[SparseMerkleProof[Digest32]]) =
    emptyState.update(
      emptyState.lastProof,
      Transaction.coinBytes(godAccount, godBalance),
      Seq(emptyState.lastProof)
    ).get
  var godProof = godProofs.head
  var currentGodBalance = godBalance
  val txAmount = 10
  (1 to numOfBlocks).foldLeft(initialState) { case (beforeBlocktree, blockNum) =>
    val (afterTree, processingTime) = (1 to txsPerBlock).foldLeft(beforeBlocktree -> 0L) { case ((tree: SparseMerkleTree[Digest32], totalTime), txNum) =>
      val recipient = hf(scala.util.Random.nextString(20))
      val tx = Transaction(txAmount, godAccount, recipient, currentGodBalance, godProof)
      val t0 = System.currentTimeMillis()
      val (updState: SparseMerkleTree[Digest32], proofs: Seq[SparseMerkleProof[Digest32]]) = Transaction.process(tx, tree).get //we generate always valid transaction
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
