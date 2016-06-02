package scorex

import scorex.crypto.hash.CryptographicHash
import scorex.crypto.hash.CryptographicHash._

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

}
