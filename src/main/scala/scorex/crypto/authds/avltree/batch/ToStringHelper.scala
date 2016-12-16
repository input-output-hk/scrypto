package scorex.crypto.authds.avltree.batch

import scorex.crypto.encode.Base58

trait ToStringHelper {
  //Needed for debug (toString) only
  protected def arrayToString(a: Array[Byte]): String = Base58.encode(a).take(8)
}
