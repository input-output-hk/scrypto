package scorex.crypto.hash

/**
 * From Wikipedia (https://en.wikipedia.org/wiki/Cryptographic_hash_function):
 * "A cryptographic hash function is a hash function which is considered practically impossible to invert,
 * that is, to recreate the input data from its hash value alone. These one-way hash functions have been
 * called "the workhorses of modern cryptography". The input data is often called the message, and
 * the hash value is often called the message digest or simply the digest.

 
  The ideal cryptographic hash function has four main properties:
    it is easy to compute the hash value for any given message
    it is infeasible to generate a message from its hash
    it is infeasible to modify a message without changing the hash
    it is infeasible to find two different messages with the same hash.
"
 */

trait CryptographicHash {

  type Digest = Array[Byte]
  type Message = Array[Byte]

  val DigestSize: Int // in bytes

  def apply(input: Message): Digest = hash(input)

  def apply(input: String): Digest = hash(input.getBytes)

  def hash(input: Message): Digest

  def hash(input: String): Digest = hash(input.getBytes)

}

