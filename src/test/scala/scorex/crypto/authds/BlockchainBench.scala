package scorex.crypto.authds


import org.h2.mvstore.MVStore
import scorex.crypto.authds.avltree.AVLTree
import scorex.crypto.authds.wtree._
import scorex.crypto.hash.Blake2b256Unsafe

import scala.reflect.io.File
import scala.util.Random


object BlockchainBench extends App {

  val blocks = 1000000

  val additionsInBlock = 200
  val modificationsInBlock = 2000
  //val removalsInBlock = 150

  val store = MVStore.open("/tmp/dbmvstore" + Random.nextInt())
  store.setCacheSize(1)

  val map = store.openMap[Array[Byte], Long]("balances")

  val hf = new Blake2b256Unsafe()

  val avl = new AVLTree()

  val balance = Array.fill(8)(0: Byte)
  val bfn = set(balance)

  val initElements = 5000000
  val keyCacheSize = 10000

  private def initStep(i: Int) = {
    if (i % 10000 == 0) println("init: i = " + i)
    map.put(hf.hash(i + "-0"), 0)

    val k = hf("1-1" + i)
    avl.modify(k, bfn, toInsertIfNotFound = true)
    k
  }

  (0 until initElements - keyCacheSize).foreach(initStep)
  val keyCache = ((initElements - keyCacheSize) until initElements).map(initStep).toArray

  store.commit()

  var size = initElements

  var last100f = 0L
  var last100l = 0L

  (0 until blocks).foreach { b =>
    size = size + additionsInBlock

    val sf0 = System.currentTimeMillis()
    (0 until additionsInBlock).foreach { k =>
      //val size = map.size()
      map.put(hf.hash(s"$k -- $b"), 0)
    }

    (0 until modificationsInBlock).foreach { _ =>
      val size = map.size()
      val k = map.getKey(Random.nextInt(size - 100) + 1)
      map.put(k, map.get(k) + 100)
    }

    /*(0 until removalsInBlock).foreach { _ =>
      val size = map.size()
      val k = map.getKey(Random.nextInt(size - 100) + 1)
      map.remove(k)
    }*/

    store.commit()
    val dsf = System.currentTimeMillis() - sf0

    last100f = last100f + dsf

    val digest0 = avl.rootHash()

    //proofs generation
    val proofs = (0 until additionsInBlock).map { i =>
      val k = hf("0" + i + ":" + b)
      avl.modify(k, bfn, toInsertIfNotFound = true)
    } ++ (0 until modificationsInBlock).map { i =>
      val k = keyCache(Random.nextInt(keyCache.length))
      avl.modify(k, bfn, toInsertIfNotFound = false)
    }

    //verification
    val sl0 = System.currentTimeMillis()
    proofs.foldLeft(digest0) { case (digest, proof) =>
      proof.verify(digest, bfn).get
    }
    val dsl = System.currentTimeMillis() - sl0

    last100l = last100l + dsl

    println(s"block #$b, elements: $size, full validation: $dsf, light validation: $dsl")

    if (b % 100 == 99) {
      val avgf = last100f / 100.0f
      val avgl = last100l / 100.0f
      val rs = s"averaged started at block #${b - 99}, full validation: $avgf, light validation: $avgl"
      println(rs)
      File("/tmp/report").appendAll(rs + "\n")
      last100f = 0L
      last100l = 0L
    }
  }

  def set(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => oldOpt.getOrElse(value) }
}
