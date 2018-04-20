package scorex.crypto.authds.avltree.batch

import scorex.utils.ScryptoLogging

trait ToStringHelper extends ScryptoLogging {
  //Needed for debug (toString) only
  protected def arrayToString(a: Array[Byte]): String = encoder.encode(a).take(8)
}
