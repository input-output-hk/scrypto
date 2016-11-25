package scrypto.crypto.authds

package object avltree {
  type Balance = Byte
  type AVLKey = Array[Byte]
  type AVLValue = Array[Byte]

  val LabelOfNone: Array[Byte] = Array()

}
