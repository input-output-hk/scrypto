package scorex.utils

object ByteArray {

  //TODO replace to fast implementation
  def compare(a1: Array[Byte], a2: Array[Byte]): Int = {
    if (a1.isEmpty && a2.isEmpty) 0
    else if (a1.isEmpty) -1
    else if (a2.isEmpty) 1
    else BigInt(a1).compare(BigInt(a2))
  }

}
