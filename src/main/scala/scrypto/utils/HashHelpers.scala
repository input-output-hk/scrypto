package scrypto.utils

import scrypto.hash.CryptographicHash


object HashHelpers {
  type Message = Array[Byte]

  def hashChain(hashes: CryptographicHash*): CryptographicHash = {
    new CryptographicHash {
      override def hash(input: Message) = applyHashes(input, hashes: _*)

      override val DigestSize: Int = hashes.head.DigestSize
    }
  }

  def applyHashes(input: Message, hashes: CryptographicHash*): Array[Byte] = {
    require(hashes.nonEmpty)
    require(hashes.forall(_.DigestSize == hashes.head.DigestSize), "Use hash algorithms with the same digest size")
    hashes.foldLeft(input)((bytes, hashFunction) => hashFunction.hash(bytes))
  }
}