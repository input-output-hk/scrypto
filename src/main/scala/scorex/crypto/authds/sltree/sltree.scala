package scorex.crypto.authds

import scorex.crypto.hash.{Blake2b256, CryptographicHash}

package object sltree {
  type SLTKey = Array[Byte]
  type SLTValue = Array[Byte]
  type Label = CryptographicHash#Digest

  val Hash = Blake2b256
  //  val LabelOfNone:Array[Byte] = Array.fill(1)(0: Byte)
  val LabelOfNone: Array[Byte] = Array()

}
