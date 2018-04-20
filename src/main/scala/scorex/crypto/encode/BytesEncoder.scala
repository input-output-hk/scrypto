package scorex.crypto.encode

import scala.util.Try

trait BytesEncoder {
  // allowed characters
  val Alphabet: String

  // encode Array[Byte] to String
  def encode(input: Array[Byte]): String

  // decode string to Array[Byte]. Return Failure on incorrect character in input
  def decode(input: String): Try[Array[Byte]]
}
