package scorex.utils

import com.typesafe.scalalogging.StrictLogging
import scorex.crypto.encode.{Base16, BytesEncoder}

trait ScryptoLogging extends StrictLogging {
  @inline protected def log = logger

  implicit val encoder: BytesEncoder = Base16
}