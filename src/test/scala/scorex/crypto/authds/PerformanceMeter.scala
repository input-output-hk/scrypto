package scorex.crypto.authds

import scorex.crypto.authds.avltree.AVLTree
import scorex.crypto.authds.treap._
import scorex.crypto.hash.Blake2b256Unsafe


object PerformanceMeter extends App with TwoPartyTests {

  val Step = 1000
  val ToCalculate = 1000
  val hash = new Blake2b256Unsafe
  val KL = 26


  val avl = new AVLTree(KL)(hash)
  val wt = new Treap()(hash)
  val treap = new Treap()(hash, Level.treapLevel)
  val elements = genElements(Step, 0, KL)
  profileTree(avl, elements, avl.rootHash())
  profileTree(wt, elements, wt.rootHash())
  profileTree(treap, elements, treap.rootHash())


  val structures = Seq("treap", "wt", "avl")
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

    val elements = genElements(Step, i, KL)
    // wt
    val wtStats: Seq[Float] = profileTree(wt, elements, wt.rootHash())
    // treap
    val treapStats: Seq[Float] = profileTree(treap, elements, treap.rootHash())
    // avl
    val avlStats = profileTree(avl, elements, avl.rootHash())

    println(s"${i * Step}, " +
      wtStats.indices.map(i => treapStats(i) + ", " + wtStats(i) + ", " + avlStats(i)).mkString(", "))
  }


}
