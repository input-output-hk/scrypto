package scorex.crypto.hash


/**
  * Thread-unsafe hash classes may be used for performance purposes
  */
trait ThreadUnsafeHash[D <: Digest] {

  val DigestSize: Int // in bytes

  def hash(inputs: Array[Byte]*): D

  def prefixedHash(prefix: Byte, inputs: Array[Byte]*): D
}
