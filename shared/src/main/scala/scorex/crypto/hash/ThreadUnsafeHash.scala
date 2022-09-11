package scorex.crypto.hash


/**
  * Thread-unsafe hash classes may be used for performance purposes
  */
trait ThreadUnsafeHash[D <: Digest] extends CryptographicHash[D]
