package scorex.crypto.authds

import scorex.crypto.hash.{CryptographicHash, Blake2b256}

package object binary {
  type SLTKey = Array[Byte]
  type SLTValue = Array[Byte]
  type Label = CryptographicHash#Digest

  val Hash = Blake2b256
  val LabelOfNone:Array[Byte] = Array()
  val Sentinel = {
    val r = new Node(Array(), Array(), 0, None, None, Array())
    r.label = r.computeLabel
    r
  }

}
