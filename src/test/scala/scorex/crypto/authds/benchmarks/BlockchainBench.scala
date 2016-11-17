package scorex.crypto.authds.benchmarks

import com.google.common.primitives.Ints
import org.mapdb.{DBMaker, Serializer}
import scorex.crypto.authds.TwoPartyDictionary.Label
import scorex.crypto.authds._
import scorex.crypto.authds.avltree.batch.{BatchAVLProver, BatchAVLVerifier, Insert}
import scorex.crypto.authds.avltree.{AVLModifyProof, AVLTree}
import scorex.crypto.authds.treap._
import scorex.crypto.hash.Blake2b256Unsafe

import scala.collection.mutable
import scala.util.{Random, Try}


trait BenchmarkCommons {
  val hf = new Blake2b256Unsafe()

  val initElements = 5000000

  val blocks = 90000

  val additionsInBlock: Int = 500
  val modificationsInBlock: Int = 1500

  val perBlock = additionsInBlock + modificationsInBlock
}

trait TwoPartyCommons extends BenchmarkCommons with UpdateF[TreapValue] {
  lazy val db = DBMaker
    .fileDB("/tmp/proofs")
    .closeOnJvmShutdown()
    .make()

  lazy val proofsMap = db.treeMap("proofs")
    .keySerializer(Serializer.INTEGER)
    .valueSerializer(Serializer.BYTE_ARRAY)
    .createOrOpen()

  def set(value: TreapValue): UpdateFunction = { oldOpt: Option[TreapValue] => Try(Some(oldOpt.getOrElse(value))) }

  lazy val balance = Array.fill(8)(0: Byte)
  lazy val bfn = set(balance)

  protected lazy val rootVar = db.atomicVar("root", Serializer.BYTE_ARRAY).createOrOpen()
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
  lazy val avl = new AVLTree(32)

  override protected def initStep(i: Int) = {
    if (i % 10000 == 0) println("init: i = " + i)
    val k = hf("1-1" + i)
    avl.modify(k, bfn).get
    k
  }

  override protected def afterInit(): Unit = {
    val rootVar = db.atomicVar("root", Serializer.BYTE_ARRAY).createOrOpen()
    rootVar.set(treeRoot)
    db.commit()
  }

  def treeRoot: Label = avl.rootHash()

  def obtainProofs(blockNum: Int): Seq[AVLModifyProof] = {
    (0 until additionsInBlock).map { i =>
      val k = hf("0" + i + ":" + blockNum)
      if (i == 1) {
        keyCache.remove(Random.nextInt(keyCache.length))
        keyCache.append(k)
      }
      avl.modify(k, bfn).get
    } ++ (0 until modificationsInBlock).map { i =>
      val k = keyCache(Random.nextInt(keyCache.length))
      avl.modify(k, bfn).get
    }
  }

  //proofs generation
  def dumpProofs(blockNum: Int, proofs: Seq[AVLModifyProof]): Unit = {
    var idx = initElements + perBlock * blockNum
    proofs.foreach { proof =>
      proofsMap.put(idx, proof.bytes)
      idx = idx + 1
    }
    db.commit()
  }

  def close() = db.close()
}


trait Batching extends TwoPartyCommons {
  lazy val rootsMap = db.treeMap("roots")
    .keySerializer(Serializer.INTEGER)
    .valueSerializer(Serializer.BYTE_ARRAY)
    .createOrOpen()
}


class BatchProver extends TwoPartyCommons with Batching with Initializing {
  val newProver = new BatchAVLProver()

  override protected def initStep(i: Int) = {
    if (i % 10000 == 0) {
      println("init: i = " + i)
      newProver.generateProof
    }
    val k = hf("1-1" + i)
    newProver.performOneModification(Insert(k, Array.fill(8)(0: Byte)))
    k
  }

  override protected def afterInit(): Unit = {
    val rootVar = db.atomicVar("root", Serializer.BYTE_ARRAY).createOrOpen()
    newProver.generateProof
    val root = newProver.rootHash
    rootVar.set(root)
    db.commit()
  }

  def obtainBatchProof(blockNum: Int): (Seq[Byte], Array[Byte], IndexedSeq[Array[Byte]]) = {
    val keys = (0 until additionsInBlock).map { i =>
      val k = hf("0" + i + ":" + blockNum)
      if (i == 1) {
        keyCache.remove(Ints.fromByteArray(Array(0:Byte) ++ k.take(3)) % keyCache.length)
        keyCache.append(k)
      }
      newProver.performOneModification(k, bfn)
      k
    } ++ (0 until modificationsInBlock).map { i =>
      val k = keyCache(Ints.fromByteArray(Array(0:Byte) ++ hf(s"p$blockNum-n$i").take(3)) % keyCache.length)
      newProver.performOneModification(k, bfn)
      k
    }

    val res = newProver.generateProof
    val root = newProver.rootHash
    (res, root, keys)
  }

  def dumpProofs(blockNum: Int, proof: Seq[Byte], root: Array[Byte], modificationKeys: IndexedSeq[Array[Byte]]): Unit = {
    proofsMap.put(blockNum, proof.toArray)

    rootsMap.put(blockNum, root)
    db.commit()
  }

  def close() = db.close()
}

class Verifier extends TwoPartyCommons {
  lazy val initRoot = rootVar.get()

  def loadProofs(blockNum: Int): Seq[AVLModifyProof] = {
    (initElements + perBlock * blockNum) until (initElements + perBlock * (blockNum + 1)) map { idx =>
      AVLModifyProof.parseBytes(proofsMap.get(idx)).get
    }
  }

  def checkProofs(rootValueBefore: Label, proofs: Seq[AVLModifyProof]): Label = {
    proofs.foldLeft(rootValueBefore) { case (root, proof) =>
      proof.verify(root, bfn).get
    }
  }
}

class BatchVerifier extends TwoPartyCommons with Batching with Initializing {

  lazy val initRoot = rootVar.get()

  def loadBlock(blockNum: Int): (Array[Byte], Array[Byte], Array[Byte]) = {
    val proof = proofsMap.get(blockNum)

    val rootBefore = if (blockNum == 1) initRoot else rootsMap.get(blockNum - 1)
    val rootAfter = rootsMap.get(blockNum)

    (proof, rootBefore, rootAfter)
  }

  def checkProofs(blockNum: Int, proof: Array[Byte], rootBefore: Label, rootAfter: Label): Unit = {
    val verifier = new BatchAVLVerifier(rootBefore, proof)
    (0 until additionsInBlock).foreach { idx =>
      val k = hf("0" + idx + ":" + blockNum)
      if (idx == 1) {
        keyCache.remove(Ints.fromByteArray(Array(0:Byte) ++ k.take(3)) % keyCache.length)
        keyCache.append(k)
      }
      verifier.verifyOneModification(k, bfn).get
    }

    (0 until modificationsInBlock).foreach { i =>
      val k = keyCache(Ints.fromByteArray(Array(0:Byte) ++ hf(s"p$blockNum-n$i").take(3)) % keyCache.length)
      val root = verifier.verifyOneModification(k, bfn).get
      if (i == additionsInBlock + modificationsInBlock - 1) assert(root sameElements rootAfter)
    }
  }

  override protected def initStep(i: Int): hf.Digest = hf("1-1" + i)

  override protected def afterInit(): Unit = {}
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
      if (k == 1) {
        keyCache.remove(Random.nextInt(keyCache.length))
        keyCache.append(keyToAdd)
      }
    }

    (0 until modificationsInBlock).foreach { _ =>
      val k = keyCache(Random.nextInt(keyCache.length))
      map.put(k, map.get(k) + 100)
    }

    store.commit()
  }
}

trait BenchmarkLaunchers extends BenchmarkCommons {
  def runFullWorker(): Unit = {
    val fw = new FullWorker
    fw.init()
    (1 to blocks).foreach { blockNum =>
      val sf0 = System.currentTimeMillis()
      fw.processBlock(blockNum)
      val sf = System.currentTimeMillis()
      val dsf = sf - sf0
      println(s"block #$blockNum, full validation: $dsf")
    }
  }

  def runProver(): Unit = {
    val p = new Prover
    p.init()

    (1 to blocks).foreach { blockNum =>
      val sf0 = System.currentTimeMillis()
      val proofs = p.obtainProofs(blockNum)
      val sf = System.currentTimeMillis()
      val dsf = sf - sf0
      p.dumpProofs(blockNum, proofs)
      println(s"block #$blockNum, prover: $dsf")

      if (blockNum % 5000 == 4999) {
        System.gc()
        Thread.sleep(60000)
      }
    }
    p.close()
  }

  def runBatchProver(): Unit = {
    val p = new BatchProver
    p.init()

    (1 to blocks).foreach { blockNum =>
      val sf0 = System.currentTimeMillis()
      val (proofs, root, modKeys) = p.obtainBatchProof(blockNum)
      val sf = System.currentTimeMillis()
      val dsf = sf - sf0
      p.dumpProofs(blockNum, proofs, root, modKeys)
      println(s"block #$blockNum, prover: $dsf")

      if (blockNum % 5000 == 4999) {
        System.gc()
        Thread.sleep(60000)
      }
    }
    p.close()
  }

  def runBatchVerifier(): Unit = {
    val v = new BatchVerifier
    v.init()

    (1 to blocks).foreach { blockNum =>
      val (proof, rootBefore, rootAfter) = v.loadBlock(blockNum)
      val sf0 = System.currentTimeMillis()
      v.checkProofs(blockNum, proof, rootBefore, rootAfter)
      val sf = System.currentTimeMillis()
      val dsf = sf - sf0
      println(s"block #$blockNum, verifier: $dsf")

      if (blockNum % 5000 == 4999) {
        System.gc()
        Thread.sleep(60000)
      }
    }
  }

  def runVerifier(): Unit = {
    val v = new Verifier
    var root = v.initRoot

    (1 to blocks).foreach { blockNum =>
      val proofs = v.loadProofs(blockNum)
      val sf0 = System.currentTimeMillis()
      root = v.checkProofs(root, proofs)
      val sf = System.currentTimeMillis()
      val dsf = sf - sf0
      println(s"block #$blockNum, verifier: $dsf")

      if (blockNum % 5000 == 4999) {
        System.gc()
        Thread.sleep(60000)
      }
    }
  }
}


object BlockchainBench extends BenchmarkLaunchers with App {
  runBatchProver()
   //runBatchVerifier()
}
