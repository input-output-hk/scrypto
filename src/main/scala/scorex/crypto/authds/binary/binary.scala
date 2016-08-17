package scorex.crypto.authds

import scorex.crypto.hash.Blake2b256

package object binary {
  type BTKey = Array[Byte]
  type BTValue = Array[Byte]
  val Hash = Blake2b256

}
