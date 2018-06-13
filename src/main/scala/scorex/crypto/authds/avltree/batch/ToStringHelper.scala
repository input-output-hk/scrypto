package scorex.crypto.authds.avltree.batch

import scorex.utils.{ScorexEncoding, ScryptoLogging}

trait ToStringHelper extends ScryptoLogging with ScorexEncoding {
  //Needed for debug (toString) only
  protected def arrayToString(a: Array[Byte]): String = encoder.encode(a).take(8)
}
