package scorex.crypto.authds


import scorex.crypto.authds.avltree.AVLTree
import scorex.crypto.authds.treap._
import scorex.crypto.hash.Blake2b256Unsafe

import scala.reflect.io.File
import scala.util.{Random, Try}

/*
trait TwoPartyCommons extends UpdateF[TreapValue] {
  val avl = new AVLTree(32)

  val hf = new Blake2b256Unsafe()

  val db = DBMaker
    .fileDB("/tmp/proofs")
    .make()

  val blocks = 1000000

  val additionsInBlock: Int = 200
  val modificationsInBlock: Int = 2000
  //val removalsInBlock = 150

  val perBlock = additionsInBlock + modificationsInBlock

  val proofsMap = db.treeMap("proofs")
    .keySerializer(Serializer.LONG)
    .valueSerializer(Serializer.BYTE_ARRAY)
    .createOrOpen()

  def set(value: TreapValue): UpdateFunction = { oldOpt: Option[TreapValue] => Try(Some(oldOpt.getOrElse(value))) }
  val balance = Array.fill(8)(0: Byte)
  val bfn = set(balance)
}

trait Initializing extends TwoPartyCommons {
  val initElements = 5000000
  val keyCacheSize = 10000

  protected def initStep(i: Int): hf.Digest

  protected def afterInit():Unit


  (0 until initElements - keyCacheSize).foreach(initStep)
  val keyCache = ((initElements - keyCacheSize) until initElements).map(initStep).toArray
  afterInit()
}

class Prover extends TwoPartyCommons with Initializing {
  override protected def initStep(i: Int) = {
    val k = hf("1-1" + i)
    avl.modify(k, bfn).get
    k
  }

  override protected def afterInit():Unit = {
  }

  //proofs generation
  def dumpProofs(blockNum:Int) = {
    val proofs = (0 until additionsInBlock).map { i =>
      val k = hf("0" + i + ":" + blockNum)
      avl.modify(k, bfn).get
    } ++ (0 until modificationsInBlock).map { i =>
      val k = keyCache(Random.nextInt(keyCache.length))
      avl.modify(k, bfn).get
    }
  }
}

class Verifier extends TwoPartyCommons {
}

class FullWorker extends TwoPartyCommons with Initializing {
  val store = MVStore.open("/tmp/dbmvstore" + Random.nextInt())
  store.setCacheSize(1)

  val map = store.openMap[Array[Byte], Long]("balances")

  override protected def initStep(i: Int) = {
    if (i % 10000 == 0) println("init: i = " + i)
    map.put(hf.hash(i + "-0"), 0)
  }

  override protected def afterInit():Unit = {
    store.commit()
  }
}


object BlockchainBench extends App with TwoPartyCommons {
  var size = initElements



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


    var last100f = 0L
    var last100l = 0L

    val dsf = System.currentTimeMillis() - sf0

    last100f = last100f + dsf

    val digest0 = avl.rootHash()



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


}
*/