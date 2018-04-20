package scorex.utils

import org.slf4j.{Logger, LoggerFactory}
import scorex.crypto.encode.{Base16, BytesEncoder}

trait ScryptoLogging {
  protected def log: Logger = LoggerFactory.getLogger(this.getClass)

  val encoder: BytesEncoder = Base16

}