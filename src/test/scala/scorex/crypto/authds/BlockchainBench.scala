package scorex.crypto.authds


import org.mapdb.{DBMaker, Serializer}
import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds.avltree.{AVLModifyProof, AVLTree}
import scorex.crypto.authds.treap._
import scorex.crypto.hash.Blake2b256Unsafe

import scala.collection.mutable
import scala.util.{Random, Try}


trait BenchmarkCommons {
  val hf = new Blake2b256Unsafe()

  val initElements = 5000000

  val blocks = 100000

  val additionsInBlock: Int = 500
  val modificationsInBlock: Int = 1500
  //val removalsInBlock = 150

  val perBlock = additionsInBlock + modificationsInBlock
}

trait TwoPartyCommons extends BenchmarkCommons with UpdateF[TreapValue] {
  val avl = new AVLTree(32)

  val db = DBMaker
    .fileDB("/tmp/proofs")
    .fileMmapEnable()
    .make()

  val proofsMap = db.treeMap("proofs")
    .keySerializer(Serializer.LONG)
    .valueSerializer(Serializer.BYTE_ARRAY)
    .createOrOpen()

  def set(value: TreapValue): UpdateFunction = { oldOpt: Option[TreapValue] => Try(Some(oldOpt.getOrElse(value))) }

  val balance = Array.fill(8)(0: Byte)
  val bfn = set(balance)
}

trait Initializing extends BenchmarkCommons {
  val keyCacheSize = 10000

  protected def initStep(i: Int): hf.Digest

  protected def afterInit(): Unit

  protected var keyCache: mutable.Buffer[hf.Digest] = mutable.Buffer()

  def init(): Unit = {
    (0 until initElements - keyCacheSize).foreach(initStep)
    keyCache.appendAll(((initElements - keyCacheSize) until initElements).map(initStep))
    afterInit()
  }
}

class Prover extends TwoPartyCommons with Initializing {
  override protected def initStep(i: Int) = {
    val k = hf("1-1" + i)
    avl.modify(k, bfn).get
    k
  }

  override protected def afterInit(): Unit = {
  }

  //proofs generation
  def dumpProofs(blockNum: Int): Unit = {
    val proofs = (0 until additionsInBlock).map { i =>
      val k = hf("0" + i + ":" + blockNum)
      avl.modify(k, bfn).get
    } ++ (0 until modificationsInBlock).map { i =>
      val k = keyCache(Random.nextInt(keyCache.length))
      avl.modify(k, bfn).get
    }

    var idx: Long = initElements + perBlock * blockNum
    proofs.foreach { proof =>
      proofsMap.put(idx, proof.bytes)
      idx = idx + 1
    }
  }
}

class Verifier extends TwoPartyCommons {
  def checkProofs(blockNum: Int, rootValueBefore: Label): Label = {
    var idx: Long = initElements + perBlock * blockNum
    var root = rootValueBefore

    while (idx < initElements + perBlock * (blockNum + 1)) {
      val proof = proofsMap.get(idx)
      root = AVLModifyProof.parseBytes(proof).get.verify(root, bfn).get
      idx = idx + 1
    }
    root
  }
}

class FullWorker extends BenchmarkCommons with Initializing {
  val store = DBMaker.fileDB("/tmp/fulldb").make()

  val map = store.treeMap("proofs")
    .keySerializer(Serializer.BYTE_ARRAY)
    .valueSerializer(Serializer.INTEGER)
    .createOrOpen()

  override protected def initStep(i: Int) = {
    if (i % 10000 == 0) println("init: i = " + i)
    val k = hf.hash(i + "-0")
    map.put(k, 0)
    k
  }

  override protected def afterInit(): Unit = {
    store.commit()
  }

  def processBlock(blockNum: Int): Unit = {
    (0 until additionsInBlock).foreach { k =>
      val keyToAdd = hf.hash(s"$k -- $blockNum")
      map.put(keyToAdd, 0)
      if(k == 1){
        keyCache.remove(Random.nextInt(keyCache.length))
        keyCache.append(keyToAdd)
      }
    }



    (0 until modificationsInBlock).foreach { _ =>
      val k = keyCache(Random.nextInt(keyCache.length))
      map.put(k, map.get(k) + 100)
    }

    /*(0 until removalsInBlock).foreach { _ =>
      val size = map.size()
      val k = map.getKey(Random.nextInt(size - 100) + 1)
      map.remove(k)
    }*/

    store.commit()
  }
}


object BlockchainBench extends App with TwoPartyCommons {

  val fw = new FullWorker
  fw.init()
  (1 to blocks).foreach{blockNum =>
    val sf0 = System.currentTimeMillis()
    fw.processBlock(blockNum)
    val sf = System.currentTimeMillis()
    val dsf = sf - sf0
    println(s"block #$blockNum, full validation: $dsf")
  }


  /*
    val sf0 = System.currentTimeMillis()



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
*/

}
