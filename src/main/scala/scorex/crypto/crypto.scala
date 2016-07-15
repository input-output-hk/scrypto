package scorex

import scorex.crypto.hash.CryptographicHash
import shapeless.{Nat, Succ}

package object crypto {
  def bytes2hex(bytes: Array[Byte]): String = bytes2hex(bytes, None)

  def bytes2hex(bytes: Array[Byte], sep: Option[String]): String =
    bytes.map("%02x".format(_)).mkString(sep.getOrElse(""))

  def hex2bytes(hex: String): Array[Byte] = {
    hex.replaceAll("[^0-9A-Fa-f]", "").sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
  }

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

  type Message = Array[Byte]

  type Nat32 = Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Nat._22]]]]]]]]]]

  type Nat40 = Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Nat32]]]]]]]]

  type Nat50 = Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Nat40]]]]]]]]]]

  type Nat60 = Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Succ[Nat50]]]]]]]]]]

  type Nat64 = Succ[Succ[Succ[Succ[Nat60]]]]


}
