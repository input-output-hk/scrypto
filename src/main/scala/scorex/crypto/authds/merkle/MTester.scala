package scorex.crypto.authds.merkle

import scorex.crypto.authds.merkle.versioned.{MvStoreVersionedMerklizedIndexedSeq, MerklizedSeqRemoval, MerklizedSeqAppend}
import scorex.crypto.authds.storage.MvStoreVersionedBlobStorage
import scorex.crypto.encode.Base16
import scorex.crypto.hash.{Blake2b256, CryptographicHash}

import scala.util.Random


object MTester extends App {

  case class UtxoLikeTreeSegment(hash: Array[Byte], data: Array[Byte]) {
    lazy val bytes = hash ++ data
  }

  def fromData[Block, HashFn <: CryptographicHash](treeFolder: String,
                                                   data: Iterable[UtxoLikeTreeSegment],
                                                   hash: HashFn): MvStoreVersionedMerklizedIndexedSeq[HashFn] = {
    lazy val utxoSeq = new MvStoreVersionedBlobStorage(Some("/tmp/" + Random.nextInt(50000)))

    data.view.zipWithIndex.foreach { case (segment, position) =>
      utxoSeq.set(position, segment.bytes)
      if (Random.nextInt(100000) == 1) utxoSeq.commit()
    }

    println("seq size: " + utxoSeq.size)

    MvStoreVersionedMerklizedIndexedSeq(Some("/tmp/" + Random.nextInt(50000)), utxoSeq, 0, hash)
  }

  val Elements = 1000

  val elems = new Iterator[UtxoLikeTreeSegment] {
    var cnt = 0

    override def hasNext: Boolean = cnt != Elements

    override def next(): UtxoLikeTreeSegment = {
      val hash = Array.fill[Byte](32)(Random.nextInt(100).toByte)
      val data = Array.fill[Byte](255)(Random.nextInt(100).toByte)
      println(s"providing an element for $cnt: " + data.hashCode())
      cnt += 1
      UtxoLikeTreeSegment(hash, data)
    }
  }.toStream


  val vms = fromData("/tmp/tree", elems, Blake2b256)

  (1 to 50).foreach { version =>
    val t0 = System.currentTimeMillis()

    val removals = (1 to (100 + Random.nextInt(1000)))
      .toList
      .map(_ => MerklizedSeqRemoval.apply(Random.nextInt(Elements)))

    val appends = (1 to (100 + Random.nextInt(3000)))
      .toList
      .map(_ => MerklizedSeqAppend(Array.fill(200)(0: Byte)))

    vms.update(Seq(), appends)
    val t = System.currentTimeMillis()

    println(s"Update #$version. Time per update: " + (t - t0))
    println(Base16.encode(vms.rootHash))
    println("seq size: " + vms.size)
    println("tree height: " + vms.tree.height)
    println("-----------------")
  }

  println("all versions: " + vms.allVersions())

  val rt = vms.allVersions().takeRight(40).head
  println(s"-----rollback to $rt--------")
  vms.rollbackTo(rt) foreach { _ =>
    println(s"-----after rollback--------")

    println(Base16.encode(vms.rootHash))
    println("seq versions: " + vms.seq.allVersions())
    println("tree versions: " + vms.tree.allVersions())
    println(vms.size)
    println(vms.tree.height)

    println("-----Finished----")
  }
}
