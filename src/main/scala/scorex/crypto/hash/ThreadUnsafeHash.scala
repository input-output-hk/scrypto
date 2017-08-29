package scorex.crypto.hash


/**
  * Thread-unsafe hash classes may be used for performance purposes
  */
trait ThreadUnsafeHash[Result <: Digest] {

  val DigestSize: Int // in bytes

  def hash(inputs: Array[Byte]*): Result

  def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Result
}
