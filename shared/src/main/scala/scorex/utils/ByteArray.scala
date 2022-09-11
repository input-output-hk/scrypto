package scorex.utils

object ByteArray {

  def compare(buffer1: Array[Byte], buffer2: Array[Byte]): Int =
    UnsignedBytes.lexicographicalComparator().compare(buffer1, buffer2)

  def concat(seq: Traversable[Array[Byte]]): Array[Byte] = {
    val length: Int = seq.map(_.length).sum
    val result: Array[Byte] = new Array[Byte](length)
    var pos: Int = 0
    seq.foreach{ array =>
      System.arraycopy(array, 0, result, pos, array.length)
      pos += array.length
    }
    result
  }
}
