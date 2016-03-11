package scorex.crypto.storage.auth

import scorex.crypto.hash.CryptographicHash._

case class MerkleProof(index: Position, merklePath: Seq[Digest])