package scorex.crypto.authds

import org.scalatest.Matchers
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
    structures.map(_ + "ProofSize").mkString(", ") + ", " +
    structures.map(_ + "LevelN").mkString(", ") + ", " +
    structures.map(_ + "LabelN").mkString(", ") + ", " +
    structures.map(_ + "KeyN").mkString(", ") + ", " +
    structures.map(_ + "ValueN").mkString(", ") + ", " +
    structures.map(_ + "BalanceN").mkString(", ") + ", " +
    structures.map(_ + "DirectionN").mkString(", "))
  (0 until ToCalculate) foreach { i =>
    val elements = genElements(Step, i)
    // wt
    val wtStats: Seq[Float] = profileTree(wt, elements, wt.rootHash())
    // treap
    val treapStats: Seq[Float] = profileTree(wt, elements, wt.rootHash())
    // avl
    val avlStats = profileTree(avl, elements, avl.rootHash())
    //slt
    val sltStats = profileTree(slt, elements, slt.rootHash())

    println(s"${i * Step}, " +
      wtStats.indices.map(i => treapStats(i) + ", " + wtStats(i) + ", " + sltStats(i) + ", " + avlStats(i)).mkString(", "))
  }


}
