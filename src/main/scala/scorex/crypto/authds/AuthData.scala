package scorex.crypto.authds

import scorex.crypto.hash.CryptographicHash

trait AuthData[HashFunction <: CryptographicHash, Proof <: DataProof]
