package scorex.crypto.authds

import org.scalatest.Matchers
import scorex.crypto.TestingCommons
import scorex.crypto.authds.sltree.SLTree
import scorex.crypto.authds.wtree._
import scorex.crypto.hash.Blake2b256


object PerformanceMeter extends App with TestingCommons with Matchers {

  val Step = 1000
  val ToCalculate = 1000

  val wt = new WTree()
  val treap = new WTree()(Blake2b256, Level.treapLevel)
  val slt = new SLTree()

  var sltDigest = slt.rootHash()

  def profileTree(tree: WTree[_], elements: Seq[Array[Byte]], inDigest: Label): (Long, Long, Long) = {
    var digest = inDigest
    val (insertTime, proofs) = time(elements.map(e => tree.modify(e, append(e))))
    val (verifyTime, _) = time {
      proofs.foreach { p =>
        digest = p.verify(digest, append(p.key)).get
      }
    }
    val proofSize = proofs.foldLeft(Array[Byte]()) { (a, b) =>
      a ++ b.proofSeq.map(_.bytes).reduce(_ ++ _)
    }.length / Step
    (insertTime, verifyTime, proofSize)
  }

  println("size, " +
    "treapInsertTime, wtInsertTime, sltInsertTime, " +
    "treapVerifyTime, wtVerifyTime, sltVerifyTime, " +
    "treapProofSize, wtProofSize,  sltProofSize")
  (0 until ToCalculate) foreach { i =>
    val elements = genElements(Step, i)
    // wt
    val (wtInsertTime, wtVerifyTime, wtProofSize) = profileTree(wt, elements, wt.rootHash())
    // treap
    val (treapInsertTime, treapVerifyTime, treapProofSize) = profileTree(wt, elements, wt.rootHash())

    //slt
    //TODO same interface for slt??
    val (sltInsertTime, sltProofs) = time(elements.map(e => slt.insert(e, append(e))))
    val (sltVerifyTime, _) = time {
      sltProofs.foreach { p =>
        assert(p._1)
        sltDigest = p._2.verify(sltDigest, append(p._2.key)).get
      }
    }
    val sltProofSize = sltProofs.foldLeft(Array[Byte]()) { (a, b) =>
      a ++ b._2.proofSeq.map(_.bytes).reduce(_ ++ _)
    }.length / Step


    println(s"${i * Step}, " +
      s"$treapInsertTime, $wtInsertTime, $sltInsertTime, " +
      s"$treapVerifyTime, $wtVerifyTime, $sltVerifyTime, " +
      s"$treapProofSize, $wtProofSize,  $sltProofSize")
  }


  def append(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => oldOpt.map(_ ++ value).getOrElse(value) }
}
