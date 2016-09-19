package scorex.crypto.authds

import scorex.crypto.authds.sltree.SLTree
import scorex.crypto.authds.wtree._
import scorex.crypto.hash._

import scala.util.Random


object PerformanceMeter extends App {

  val wt = new WTree()
  val slt = new SLTree()

  val Step = 1000
  val ToCalculate = 1000

  var wtDigest = wt.rootHash()
  var sltDigest = slt.rootHash()
  (0 until ToCalculate) foreach { i =>
    val elements = genElements(Step, i)
    // wt
    val (wtInsertTime, wtProofs) = time(elements.map(e => wt.modify(e._1, append(e._1))))
    val (wtVerifyTime, _) = time {
      wtProofs.foreach { p =>
        wtDigest = p.verify(wtDigest, append(p.x)).get
      }
    }
    val wtProofSize = wtProofs.foldLeft(Array[Byte]()) { (a, b) =>
      a ++ b.proofSeq.map(_.bytes).reduce(_ ++ _)
    }.length / Step

    //slt

    val (sltInsertTime, sltProofs) = time(elements.map(e => slt.insert(e._1, append(e._1))))
    val (sltVerifyTime, _) = time {
      sltProofs.foreach { p =>
        assert(p._1)
        sltDigest = p._2.verify(sltDigest, append(p._2.key)).get
      }
    }
    val sltProofSize = sltProofs.foldLeft(Array[Byte]()) { (a, b) =>
      a ++ b._2.proofSeq.map(_.bytes).reduce(_ ++ _)
    }.length / Step


    println(s"${i * Step} => $wtInsertTime, $wtVerifyTime, $wtProofSize, $sltInsertTime, $sltVerifyTime, $sltProofSize")
  }


  def genElements(howMany: Int, seed: Long): Seq[(WTKey, WTValue)] = {
    val r = Random
    r.setSeed(seed)
    (0 until howMany).map { l =>
      (Sha256(r.nextString(16).getBytes), Sha256(r.nextString(16).getBytes))
    }
  }

  def time[R](block: => R): (Long, R) = {
    val t0 = System.currentTimeMillis()
    val result = block // call-by-name
    val t1 = System.currentTimeMillis()
    (t1 - t0, result)
  }

  def append(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => oldOpt.map(_ ++ value).getOrElse(value) }
}
