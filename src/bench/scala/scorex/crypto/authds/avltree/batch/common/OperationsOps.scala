package scorex.crypto.authds.avltree.batch.common

import com.google.common.primitives.Longs
import scorex.crypto.authds.avltree.batch.common.PreparedAVLBatchProver.Config
import scorex.crypto.authds.avltree.batch.{Insert, Operation, Remove}
import scorex.crypto.authds.{ADKey, ADValue}

import scala.util.Random

trait OperationsOps {

  def generateInserts(r: Range)(implicit cfg: Config): Seq[Operation] =
    r.map { i =>
      val key = new Array[Byte](cfg.kl)
      val k = Longs.toByteArray(i)
      k.copyToArray(key)
      Insert(ADKey @@ key, ADValue @@ k.take(cfg.vl))
    }

  def generateDeletes(inserts: Seq[Operation], count: Int): Seq[Operation] =
    Random.shuffle(inserts).take(count).map { in => Remove(in.key)}

}
