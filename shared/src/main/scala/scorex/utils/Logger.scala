package scorex.utils

abstract class Logger {
  def error(message: String): Unit
}

object Logger {
  val Default = new Logger {
    override def error(message: String): Unit = {
      println(message)
    }
  }
}
