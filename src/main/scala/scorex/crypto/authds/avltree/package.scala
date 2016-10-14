package scorex.crypto.authds

import scorex.crypto.hash.CryptographicHash

import scala.util.Try

package object avltree {
  type Balance = Byte
  type AVLKey = Array[Byte]
  type AVLValue = Array[Byte]
  type Label = CryptographicHash#Digest

  val LabelOfNone: Array[Byte] = Array()

}
