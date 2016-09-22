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

  val structures = Seq("treap", "wt", "slt", "avl")
  println("size, " +
    structures.map(_ + "InsertTime").mkString(", ") + ", " +
    structures.map(_ + "VerifyTime").mkString(", ") + ", " +
    structures.map(_ + "ProofSize").mkString(", "))
  (0 until ToCalculate) foreach { i =>
    val elements = genElements(Step, i)
    // wt
    val wtStats:Seq[Float] = profileTree(wt, elements, wt.rootHash())
    // treap
    val treapStats:Seq[Float] = profileTree(wt, elements, wt.rootHash())
    // avl
    //    val avlStats = profileTree(avl, elements, avl.rootHash())
    val avlStats:Seq[Float] = Seq(-1, -1, -1, -1, -1, -1, -1, -1, -1)


    //slt
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
    val sltStats:Seq[Float] = Seq(sltInsertTime, sltVerifyTime, sltProofSize)


    println(s"${i * Step}, " +
      wtStats.indices.map(i => treapStats(i) + ", " + wtStats(i) + ", " + sltStats(i) + ", " + avlStats(i)).mkString(", "))
  }


}
