package scorex.crypto.authds

import scorex.crypto.hash.{Blake2b256, CryptographicHash}

package object sltree {
  type SLTKey = Array[Byte]
  type SLTValue = Array[Byte]
  type Label = CryptographicHash#Digest

  val LabelOfNone: Array[Byte] = Array()
  type UpdateFunction =  Option[SLTValue] => SLTValue

}
