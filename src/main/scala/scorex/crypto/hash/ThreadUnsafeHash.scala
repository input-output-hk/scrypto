package scorex.crypto.hash


/**
  * Thread-unsafe hash classes may be used for performance purposes
  */
trait ThreadUnsafeHash {

  def hash(inputs: Array[Byte]*): Array[Byte]

  def prefixedHash(prefix: Byte, inputs: Array[Byte]*): Array[Byte]
}
