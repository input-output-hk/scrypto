package scorex.crypto.authds

import scorex.crypto.hash.Blake2b256

package object binary {
  type SLTKey = Array[Byte]
  type SLTValue = Array[Byte]
  val Hash = Blake2b256
  val LabelOfNone:Array[Byte] = Array()

}
