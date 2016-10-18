package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import scorex.crypto.authds.DataProof
import scorex.crypto.encode._
import scorex.crypto.hash.CryptographicHash

import scala.util.Try


case class SLPath(levHashes: Seq[LevHash]) extends DataProof {

  lazy val hashes: Seq[CryptographicHash#Digest] = levHashes.map(_.h)
  lazy val levels: Seq[Int] = levHashes.map(_.l)

  override def toString: String = levHashes.mkString(", ")
}

case class LevHash(h: CryptographicHash#Digest, l: Int, d: Direction) {
  override def toString: String = s"${Base58.encode(h).take(12)}|$l|$d"

  lazy val bytes: Array[Byte] = {
    Ints.toByteArray(l) ++ d.bytes ++ h
  }
}

object LevHash {
  def parseBytes(bytes: Array[Byte]): Try[LevHash] = Try {
    val lev = Ints.fromByteArray(bytes.slice(0, 4))
    val d = if (bytes.slice(4, 5).head == (0: Byte)) Right else Down
    val hash = bytes.slice(5, bytes.length)
    LevHash(hash, lev, d)
  }
}

sealed trait Direction {
  def bytes: Array[Byte]
}

case object Right extends Direction {
  lazy val bytes: Array[Byte] = Array(0: Byte)
}

case object Down extends Direction {
  lazy val bytes: Array[Byte] = Array(1: Byte)
}