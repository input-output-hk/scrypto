package scorex.crypto.authds

import org.scalatest.Matchers
import scorex.crypto.authds.avltree.AVLTree
import scorex.crypto.authds.sltree.SLTree
import scorex.crypto.authds.wtree._
import scorex.crypto.hash.{Sha256Unsafe, Blake2b256Unsafe}


object PerformanceMeter extends App with TwoPartyTests {

  val Step = 1000
  val ToCalculate = 1000
  //  val hash = new Sha256Unsafe
  val hash = new Blake2b256Unsafe

  val avl = new AVLTree()(hash)
  val wt = new WTree()(hash)
  val treap = new WTree()(hash, Level.treapLevel)
  val slt = new SLTree()(hash)
  val elements = genElements(Step, 0, 26)
  profileTree(avl, elements, avl.rootHash())
  profileTree(wt, elements, wt.rootHash())
  profileTree(treap, elements, treap.rootHash())
  profileTree(slt, elements, slt.rootHash())


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
  (1 until ToCalculate) foreach { i =>
    System.gc()

    val elements = genElements(Step, i, 26)
    // wt
    val wtStats: Seq[Float] = profileTree(wt, elements, wt.rootHash())
    // treap
    val treapStats: Seq[Float] = profileTree(treap, elements, treap.rootHash())
    // avl
    val avlStats = profileTree(avl, elements, avl.rootHash())
    //slt
    val sltStats = profileTree(slt, elements, slt.rootHash())

    println(s"${i * Step}, " +
      wtStats.indices.map(i => treapStats(i) + ", " + wtStats(i) + ", " + sltStats(i) + ", " + avlStats(i)).mkString(", "))
  }


}
