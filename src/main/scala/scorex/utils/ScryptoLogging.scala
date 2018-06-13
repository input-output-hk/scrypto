package scorex.utils

import com.typesafe.scalalogging.StrictLogging

/**
  * Trait with logger
  * TODO extract to ScorexUtils
  */
trait ScryptoLogging extends StrictLogging {
  @inline protected def log = logger

}