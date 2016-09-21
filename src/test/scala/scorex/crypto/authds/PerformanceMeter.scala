package scorex.crypto.authds

import org.scalatest.Matchers
import scorex.crypto.TestingCommons
import scorex.crypto.authds.avltree.AVLTree
import scorex.crypto.authds.sltree.SLTree
import scorex.crypto.authds.wtree._
import scorex.crypto.hash.Blake2b256


object PerformanceMeter extends App with TwoPartyTests with Matchers {

  val Step = 1000
  val ToCalculate = 1000

  val avl = new AVLTree()
  val wt = new WTree()
  val treap = new WTree()(Blake2b256, Level.treapLevel)
  val slt = new SLTree()

  var sltDigest = slt.rootHash()

  println("size, " +
    "treapInsertTime, wtInsertTime, sltInsertTime, avlInsertTime, " +
    "treapVerifyTime, wtVerifyTime, sltVerifyTime, avlVerifyTime, " +
    "treapProofSize, wtProofSize,  sltProofSize, avlProofSize")
  (0 until ToCalculate) foreach { i =>
    val elements = genElements(Step, i)
    // wt
    val (wtInsertTime, wtVerifyTime, wtProofSize) = profileTree(wt, elements, wt.rootHash())
    // treap
    val (treapInsertTime, treapVerifyTime, treapProofSize) = profileTree(wt, elements, wt.rootHash())
    // avl
    val (avlInsertTime, avlVerifyTime, avlProofSize) = profileTree(avl, elements, avl.rootHash())


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
      s"$treapInsertTime, $wtInsertTime, $sltInsertTime, $avlInsertTime, " +
      s"$treapVerifyTime, $wtVerifyTime, $sltVerifyTime, $avlVerifyTime, " +
      s"$treapProofSize, $wtProofSize,  $sltProofSize, $avlProofSize")
  }


}
