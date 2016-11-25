package scrypto.hash


/**
  * Thread-unsafe hash classes may be used for performance purposes
  */
trait ThreadUnsafeHash {

  val DigestSize: Int // in bytes

  def hash(inputs: Array[Byte]*): Array[Byte]

  def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Array[Byte]
}
