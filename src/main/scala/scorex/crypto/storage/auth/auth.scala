package scorex.crypto.storage

import scorex.crypto.hash.Blake2b256

package object auth {
  type Position = Long
  val DefaultHash = Blake2b256
}
