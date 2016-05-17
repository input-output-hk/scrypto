package scorex.crypto.authds

import scorex.crypto.authds.merkle.DataProof
import scorex.crypto.hash.CryptographicHash

/**
  * Created by kushti on 17.05.16.
  */
trait AuthData[HashFunction <: CryptographicHash, Proof <: DataProof]
