package scorex.crypto.storage

import scorex.crypto.hash.Blake2b256

package object auth {
  type Position = Long
  val DefaultHashFunction = Blake2b256
}
