package scorex.crypto.authds

import org.scalatest.Matchers
import scorex.crypto.authds.avltree.AVLTree


object AvlProfiling extends App with TwoPartyTests with Matchers {

  val Step = 1000
  val ToCalculate = 10000

  val avl = new AVLTree()

  val structures = Seq("avl")
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
    // avl
    val avlStats = profileTree(avl, elements, avl.rootHash())
    println(s"${i * Step}, " + avlStats.indices.map(i => avlStats(i)).mkString(", "))
  }


}
